import mongoose, { type ClientSession, Types } from "mongoose";
import { env } from "../config/env";
import { generateOtpCode, otpEmailPayload } from "../config/mailer";
import {
  EmailOutbox,
  OtpChallenge,
  OtpRateLimit,
  type IOtpChallenge,
  type OtpPurpose,
} from "../models/mongoose";
import { normalizeEmail, normalizeUaeMobile } from "../utils/identity";
import {
  assertOtpCryptoReady,
  computeOtpHmac,
  encryptOutboxPayload,
  generateChallengeId,
  generateChallengeNonce,
  generateResetJti,
  verifyOtpHmacDigest,
} from "../utils/otpCrypto";
import {
  createOutboxDocument,
  nudgeEmailOutboxWorker,
} from "./emailOutbox.service";

export const OTP_TTL_MS = 5 * 60 * 1000; // 5 minutes
export const OTP_RESEND_COOLDOWN_MS = 120 * 1000; // 120 seconds
export const OTP_MAX_ATTEMPTS = 5;
export const OTP_MAX_RESENDS = 3;
export const CHALLENGE_SESSION_MAX_AGE_MS = 15 * 60 * 1000;
export const CHALLENGE_RETENTION_MS = 24 * 60 * 60 * 1000;
export const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
export const RESET_TOKEN_TTL_MS = 10 * 60 * 1000;

export const IP_REQUEST_LIMIT = 30;
export const EMAIL_REQUEST_LIMIT = 8;
export const PHONE_REQUEST_LIMIT = 8;
export const IP_VERIFY_LIMIT = 40;
export const EMAIL_VERIFY_LIMIT = 20;

const PURPOSE_EMAIL_PHRASES: Record<OtpPurpose, string> = {
  customer_signup: "complete your account signup",
  customer_login: "log in to your account",
  admin_login: "log in to your account",
  password_reset: "reset your password",
  profile_update: "verify your email address",
  pos_counter_verify: "verify your email address",
};

export type OtpFailureCode =
  | "INVALID_EMAIL"
  | "RATE_LIMITED"
  | "RESEND_COOLDOWN"
  | "MAX_RESENDS_EXCEEDED"
  | "CHALLENGE_MISSING"
  | "CHALLENGE_INVALID"
  | "CHALLENGE_EXPIRED"
  | "CHALLENGE_CONSUMED"
  | "CHALLENGE_LOCKED"
  | "AUTH_NOT_VERIFIED"
  | "TOKEN_VERSION_MISMATCH"
  | "INVALID_OTP"
  | "RESET_TOKEN_INVALID"
  | "RESET_TOKEN_USED";

/**
 * Sentinel error thrown inside `session.withTransaction(...)` to force MongoDB to
 * abort and roll back prior transaction writes (such as `consumedAt` / `resetTokenConsumedAt`)
 * when a downstream business check or mutation fails, without triggering transient retries.
 */
export class TxAbortError extends Error {
  constructor(message = "TRANSACTION_ABORTED") {
    super(message);
    this.name = "TxAbortError";
  }
}

export type RateLimitConsumeResult =
  | { allowed: true; remaining: number; resetAt: Date }
  | { allowed: false; retryAfterSeconds: number; resetAt: Date };

export interface IssueChallengeParams {
  purpose: OtpPurpose;
  email: string;
  toName?: string;
  ip?: string;
  phone?: string;
  isDecoy?: boolean;
  authVerified?: boolean;
  userId?: string | Types.ObjectId | null;
  tokenVersionSnapshot?: number | null;
  pendingData?: Record<string, unknown> | null;
  maxAttempts?: number;
  maxResends?: number;
  ttlMs?: number;
  now?: Date;
  session?: ClientSession;
}

export type IssueChallengeResult =
  | {
      ok: true;
      challengeId: string;
      outboxId: string;
      expiresAt: Date;
      expiresInSeconds: number;
      resendAfterSeconds: number;
    }
  | {
      ok: false;
      code: OtpFailureCode;
      httpStatus: number;
      message: string;
      retryAfterSeconds?: number;
    };

export interface ResendChallengeParams {
  purpose: OtpPurpose;
  email: string;
  challengeId: string;
  userId?: string | Types.ObjectId | null;
  requireAuthVerified?: boolean;
  expectedTokenVersion?: number | null;
  ip?: string;
  toName?: string;
  ttlMs?: number;
  now?: Date;
}

export interface VerifyChallengeParams {
  purpose: OtpPurpose;
  email: string;
  otp: string;
  challengeId?: string;
  userId?: string | Types.ObjectId | null;
  requireAuthVerified?: boolean;
  expectedTokenVersion?: number | null;
  ip?: string;
  now?: Date;
  session?: ClientSession;
}

export type VerifyChallengeResult =
  | {
      ok: true;
      challenge: IOtpChallenge;
    }
  | {
      ok: false;
      code: OtpFailureCode;
      httpStatus: number;
      message: string;
      attemptsRemaining?: number;
      retryAfterSeconds?: number;
    };

const toObjectIdOrNull = (
  id: string | Types.ObjectId | null | undefined,
): Types.ObjectId | null => {
  if (!id) return null;
  if (id instanceof Types.ObjectId) return id;
  return Types.ObjectId.isValid(id) ? new Types.ObjectId(id) : null;
};

const isDuplicateKeyError = (err: unknown): boolean => {
  if (typeof err !== "object" || err === null) return false;
  const e = err as { code?: number; cause?: { code?: number } };
  return e.code === 11000 || e.cause?.code === 11000;
};

const isRetryableTxConflict = (err: unknown): boolean => {
  if (isDuplicateKeyError(err)) return true;
  if (typeof err !== "object" || err === null) return false;
  const e = err as { code?: number; errorLabels?: unknown };
  if (
    Array.isArray(e.errorLabels) &&
    e.errorLabels.includes("TransientTransactionError")
  ) {
    return true;
  }
  return e.code === 112;
};

const suppressPendingOutboxesForChallenges = async (
  challengeIds: string[],
  now: Date = new Date(),
  session?: ClientSession,
): Promise<void> => {
  if (challengeIds.length === 0) return;
  const cleanupAt = new Date(now.getTime() + CHALLENGE_RETENTION_MS);
  await EmailOutbox.updateMany(
    {
      challengeId: { $in: challengeIds },
      status: "pending",
    },
    {
      $set: {
        status: "suppressed",
        cleanupAt,
      },
      $unset: { encryptedPayload: 1 },
    },
    session ? { session } : undefined,
  );
};

const runWithOptionalTransaction = async <T>(
  providedSession: ClientSession | undefined,
  fn: (session: ClientSession) => Promise<T>,
): Promise<T> => {
  if (providedSession) {
    return fn(providedSession);
  }
  const session = await mongoose.startSession();
  try {
    let result!: T;
    await session.withTransaction(async () => {
      result = await fn(session);
    });
    return result;
  } finally {
    await session.endSession();
  }
};

/**
 * Ensures new PR 2 OTP/RateLimit/EmailOutbox collections and indexes exist before
 * multi-document ACID transactions run. Never touches existing `User` indexes.
 */
export const ensureOtpCollectionsInitialized = async (): Promise<void> => {
  await Promise.all([
    OtpChallenge.init(),
    OtpRateLimit.init(),
    EmailOutbox.init(),
  ]);
};

/**
 * Atomically consumes one unit from a persistent MongoDB sliding/fixed window bucket.
 * Handles expired bucket resets and concurrent first-insert E11000 races safely.
 */
export const consumeRateLimitBucket = async (params: {
  key: string;
  scope: string;
  limit: number;
  windowMs: number;
  now?: Date;
}): Promise<RateLimitConsumeResult> => {
  const now = params.now ?? new Date();
  const cleanupAt = new Date(
    now.getTime() + Math.max(params.windowMs * 2, CHALLENGE_RETENTION_MS),
  );
  const nextResetAt = new Date(now.getTime() + params.windowMs);

  for (let attempt = 0; attempt < 8; attempt += 1) {
    const active = await OtpRateLimit.findOneAndUpdate(
      { key: params.key, resetAt: { $gt: now }, count: { $lt: params.limit } },
      { $inc: { count: 1 }, $set: { lastActionAt: now, cleanupAt } },
      { new: true },
    );
    if (active) {
      return {
        allowed: true,
        remaining: Math.max(0, params.limit - active.count),
        resetAt: active.resetAt,
      };
    }

    const resetDoc = await OtpRateLimit.findOneAndUpdate(
      { key: params.key, resetAt: { $lte: now } },
      {
        $set: {
          scope: params.scope,
          count: 1,
          resetAt: nextResetAt,
          lastActionAt: now,
          cleanupAt,
        },
      },
      { new: true },
    );
    if (resetDoc) {
      return {
        allowed: true,
        remaining: Math.max(0, params.limit - 1),
        resetAt: resetDoc.resetAt,
      };
    }

    const existing = await OtpRateLimit.findOne({ key: params.key })
      .select("count resetAt")
      .lean();
    if (!existing) {
      try {
        const created = await OtpRateLimit.create({
          key: params.key,
          scope: params.scope,
          count: 1,
          resetAt: nextResetAt,
          lastActionAt: now,
          cleanupAt,
        });
        return {
          allowed: true,
          remaining: Math.max(0, params.limit - created.count),
          resetAt: created.resetAt,
        };
      } catch (err) {
        if (isDuplicateKeyError(err)) {
          continue;
        }
        throw err;
      }
    }

    if (existing.resetAt.getTime() <= now.getTime() || existing.count < params.limit) {
      continue;
    }

    const retryAfterSeconds = Math.max(
      1,
      Math.ceil((existing.resetAt.getTime() - now.getTime()) / 1000),
    );
    return {
      allowed: false,
      retryAfterSeconds,
      resetAt: existing.resetAt,
    };
  }

  const fallbackExisting = await OtpRateLimit.findOne({ key: params.key })
    .select("resetAt")
    .lean();
  const resetAt = fallbackExisting?.resetAt ?? nextResetAt;
  return {
    allowed: false,
    retryAfterSeconds: Math.max(1, Math.ceil((resetAt.getTime() - now.getTime()) / 1000)),
    resetAt,
  };
};

/**
 * Sets or updates the persistent resend cooldown window in `OtpRateLimit`.
 * In initial-issue mode (`enforceCooldown: false`), records the new cooldown timestamp.
 * In resend mode (`enforceCooldown: true`), atomically denies calls inside `cooldownMs`.
 */
const touchPersistentCooldownBucket = async (params: {
  key: string;
  cooldownMs: number;
  now: Date;
  enforceCooldown: boolean;
}): Promise<RateLimitConsumeResult> => {
  const { key, cooldownMs, now, enforceCooldown } = params;
  const nextResetAt = new Date(now.getTime() + cooldownMs);
  const cleanupAt = new Date(now.getTime() + CHALLENGE_RETENTION_MS);

  if (!enforceCooldown) {
    await OtpRateLimit.findOneAndUpdate(
      { key },
      {
        $set: {
          scope: "resend_cooldown",
          count: 1,
          resetAt: nextResetAt,
          lastActionAt: now,
          cleanupAt,
        },
      },
      { upsert: true, new: true },
    );
    return { allowed: true, remaining: 0, resetAt: nextResetAt };
  }

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const allowedDoc = await OtpRateLimit.findOneAndUpdate(
      { key, resetAt: { $lte: now } },
      {
        $set: {
          scope: "resend_cooldown",
          count: 1,
          resetAt: nextResetAt,
          lastActionAt: now,
          cleanupAt,
        },
      },
      { new: true },
    );
    if (allowedDoc) {
      return { allowed: true, remaining: 0, resetAt: allowedDoc.resetAt };
    }

    const existing = await OtpRateLimit.findOne({ key }).select("resetAt").lean();
    if (!existing) {
      try {
        const created = await OtpRateLimit.create({
          key,
          scope: "resend_cooldown",
          count: 1,
          resetAt: nextResetAt,
          lastActionAt: now,
          cleanupAt,
        });
        return { allowed: true, remaining: 0, resetAt: created.resetAt };
      } catch (err) {
        if (isDuplicateKeyError(err)) continue;
        throw err;
      }
    }

    if (existing.resetAt.getTime() <= now.getTime()) {
      continue;
    }

    return {
      allowed: false,
      retryAfterSeconds: Math.max(
        1,
        Math.ceil((existing.resetAt.getTime() - now.getTime()) / 1000),
      ),
      resetAt: existing.resetAt,
    };
  }

  return {
    allowed: false,
    retryAfterSeconds: Math.ceil(cooldownMs / 1000),
    resetAt: nextResetAt,
  };
};

const enforceIssuanceQuotas = async (params: {
  purpose: OtpPurpose;
  normalizedEmail: string;
  ip?: string;
  phone?: string;
  now: Date;
}): Promise<{ ok: true } | { ok: false; retryAfterSeconds: number }> => {
  const ipKey = (params.ip || "unknown").trim() || "unknown";

  const ipRes = await consumeRateLimitBucket({
    key: `ip_req:${params.purpose}:${ipKey}`,
    scope: "ip_req",
    limit: IP_REQUEST_LIMIT,
    windowMs: RATE_LIMIT_WINDOW_MS,
    now: params.now,
  });
  if (!ipRes.allowed) {
    return { ok: false, retryAfterSeconds: ipRes.retryAfterSeconds };
  }

  const emailRes = await consumeRateLimitBucket({
    key: `email_req:${params.purpose}:${params.normalizedEmail}`,
    scope: "email_req",
    limit: EMAIL_REQUEST_LIMIT,
    windowMs: RATE_LIMIT_WINDOW_MS,
    now: params.now,
  });
  if (!emailRes.allowed) {
    return { ok: false, retryAfterSeconds: emailRes.retryAfterSeconds };
  }

  if (params.phone) {
    const cleanPhone = normalizeUaeMobile(params.phone) ?? params.phone.trim();
    if (cleanPhone) {
      const phoneRes = await consumeRateLimitBucket({
        key: `phone_req:${params.purpose}:${cleanPhone}`,
        scope: "phone_req",
        limit: PHONE_REQUEST_LIMIT,
        windowMs: RATE_LIMIT_WINDOW_MS,
        now: params.now,
      });
      if (!phoneRes.allowed) {
        return { ok: false, retryAfterSeconds: phoneRes.retryAfterSeconds };
      }
    }
  }

  return { ok: true };
};

const enforceVerifyQuotas = async (params: {
  purpose: OtpPurpose;
  normalizedEmail: string;
  ip?: string;
  now: Date;
}): Promise<{ ok: true } | { ok: false; retryAfterSeconds: number }> => {
  const ipKey = (params.ip || "unknown").trim() || "unknown";

  const ipRes = await consumeRateLimitBucket({
    key: `ip_verify:${params.purpose}:${ipKey}`,
    scope: "ip_verify",
    limit: IP_VERIFY_LIMIT,
    windowMs: RATE_LIMIT_WINDOW_MS,
    now: params.now,
  });
  if (!ipRes.allowed) {
    return { ok: false, retryAfterSeconds: ipRes.retryAfterSeconds };
  }

  const emailRes = await consumeRateLimitBucket({
    key: `email_verify:${params.purpose}:${params.normalizedEmail}`,
    scope: "email_verify",
    limit: EMAIL_VERIFY_LIMIT,
    windowMs: RATE_LIMIT_WINDOW_MS,
    now: params.now,
  });
  if (!emailRes.allowed) {
    return { ok: false, retryAfterSeconds: emailRes.retryAfterSeconds };
  }

  return { ok: true };
};

/**
 * Generates an opaque OTP challenge + encrypted EmailOutbox job (or suppressed decoy pair)
 * inside a MongoDB ACID transaction, invalidating prior active challenges for the same identity.
 */
export const issueChallengeAndEnqueueOutbox = async (
  params: IssueChallengeParams,
): Promise<IssueChallengeResult> => {
  assertOtpCryptoReady();

  const normalizedEmail = normalizeEmail(params.email);
  if (!normalizedEmail) {
    return {
      ok: false,
      code: "INVALID_EMAIL",
      httpStatus: 400,
      message: "A valid email address is required.",
    };
  }

  const now = params.now ?? new Date();
  const isDecoy = Boolean(params.isDecoy);
  const ttlMs = params.ttlMs ?? OTP_TTL_MS;
  const maxAttempts = params.maxAttempts ?? OTP_MAX_ATTEMPTS;
  const maxResends = params.maxResends ?? OTP_MAX_RESENDS;
  const expiresAt = new Date(now.getTime() + ttlMs);
  const cleanupAt = new Date(now.getTime() + CHALLENGE_RETENTION_MS);

  const quotaResult = await enforceIssuanceQuotas({
    purpose: params.purpose,
    normalizedEmail,
    ip: params.ip,
    phone: params.phone,
    now,
  });
  if (!quotaResult.ok) {
    return {
      ok: false,
      code: "RATE_LIMITED",
      httpStatus: 429,
      message: `Too many verification requests. Please wait ${quotaResult.retryAfterSeconds} seconds before trying again.`,
      retryAfterSeconds: quotaResult.retryAfterSeconds,
    };
  }

  const otpCode = generateOtpCode();
  const challengeId = generateChallengeId();
  const challengeNonce = generateChallengeNonce();
  const otpHash = isDecoy
    ? computeOtpHmac({
        purpose: params.purpose,
        normalizedEmail,
        challengeId,
        challengeNonce,
        otp: generateChallengeNonce(),
      })
    : computeOtpHmac({
        purpose: params.purpose,
        normalizedEmail,
        challengeId,
        challengeNonce,
        otp: otpCode,
      });

  const userObjectId = toObjectIdOrNull(params.userId);
  const purposePhrase = PURPOSE_EMAIL_PHRASES[params.purpose];
  const emailPayloadSpec = otpEmailPayload(otpCode, purposePhrase);
  const encryptedPayload = isDecoy
    ? null
    : encryptOutboxPayload({
        to: normalizedEmail,
        toName: params.toName?.trim() || normalizedEmail,
        templateId: emailPayloadSpec.templateId || env.MSG91_TEMPLATE_OTP,
        variables: emailPayloadSpec.variables,
      });

  await ensureOtpCollectionsInitialized();

  let created!: { challengeId: string; outboxId: string };
  const maxTxAttempts = params.session ? 1 : 5;
  for (let txAttempt = 0; txAttempt < maxTxAttempts; txAttempt += 1) {
    try {
      created = await runWithOptionalTransaction(params.session, async (session) => {
        const activeFilter: Record<string, unknown> = {
          purpose: params.purpose,
          consumedAt: null,
          invalidatedAt: null,
          $or: [{ email: normalizedEmail }],
        };
        if (userObjectId) {
          (activeFilter.$or as Array<Record<string, unknown>>).push({ userId: userObjectId });
        }

        const oldActive = await OtpChallenge.find(activeFilter)
          .select("challengeId")
          .session(session)
          .lean();
        const oldIds = oldActive.map((doc) => doc.challengeId);

        if (oldIds.length > 0) {
          await OtpChallenge.updateMany(
            { challengeId: { $in: oldIds }, consumedAt: null, invalidatedAt: null },
            { $set: { invalidatedAt: now } },
            { session },
          );
          await suppressPendingOutboxesForChallenges(oldIds, now, session);
        }

        const challengeDoc = new OtpChallenge({
          challengeId,
          email: normalizedEmail,
          purpose: params.purpose,
          otpHash,
          challengeNonce,
          isDecoy,
          authVerified: Boolean(params.authVerified),
          userId: userObjectId,
          tokenVersionSnapshot:
            typeof params.tokenVersionSnapshot === "number"
              ? params.tokenVersionSnapshot
              : null,
          pendingData: params.pendingData ?? null,
          attempts: 0,
          maxAttempts,
          resendCount: 0,
          maxResends,
          lastSentAt: now,
          lastAttemptAt: null,
          expiresAt,
          consumedAt: null,
          lockedAt: null,
          invalidatedAt: null,
          outboxId: null,
          deliveryStatus: isDecoy ? "suppressed" : "pending",
          cleanupAt,
        });

        const outboxDoc = await createOutboxDocument(
          {
            challengeId,
            purpose: params.purpose,
            status: isDecoy ? "suppressed" : "pending",
            encryptedPayload,
            now,
          },
          session,
        );

        challengeDoc.outboxId = outboxDoc.outboxId;
        await challengeDoc.save({ session });

        return {
          challengeId: challengeDoc.challengeId,
          outboxId: outboxDoc.outboxId,
        };
      });
      break;
    } catch (err: unknown) {
      if (txAttempt + 1 < maxTxAttempts && isRetryableTxConflict(err)) {
        continue;
      }
      throw err;
    }
  }

  await touchPersistentCooldownBucket({
    key: `cooldown:${params.purpose}:${normalizedEmail}`,
    cooldownMs: OTP_RESEND_COOLDOWN_MS,
    now,
    enforceCooldown: false,
  });

  if (!isDecoy && !params.session) {
    nudgeEmailOutboxWorker();
  }

  return {
    ok: true,
    challengeId: created.challengeId,
    outboxId: created.outboxId,
    expiresAt,
    expiresInSeconds: Math.round(ttlMs / 1000),
    resendAfterSeconds: Math.round(OTP_RESEND_COOLDOWN_MS / 1000),
  };
};

/**
 * Resends OTP for an active, unconsumed, unlocked challenge by invalidating the
 * superseded challenge, enforcing 120s cooldown & max 3 resends, and issuing a
 * replacement OtpChallenge + EmailOutbox inside a MongoDB ACID transaction.
 */
export const resendChallengeAndEnqueueOutbox = async (
  params: ResendChallengeParams,
): Promise<IssueChallengeResult> => {
  assertOtpCryptoReady();

  const normalizedEmail = normalizeEmail(params.email);
  if (!normalizedEmail) {
    return {
      ok: false,
      code: "INVALID_EMAIL",
      httpStatus: 400,
      message: "A valid email address is required.",
    };
  }

  if (!params.challengeId || typeof params.challengeId !== "string") {
    return {
      ok: false,
      code: "CHALLENGE_MISSING",
      httpStatus: 401,
      message: "Active verification session is required before resending OTP.",
    };
  }

  const now = params.now ?? new Date();
  const ttlMs = params.ttlMs ?? OTP_TTL_MS;
  const userObjectId = toObjectIdOrNull(params.userId);

  const existing = await OtpChallenge.findOne({
    challengeId: params.challengeId,
    purpose: params.purpose,
    email: normalizedEmail,
  });

  if (!existing) {
    return {
      ok: false,
      code: "CHALLENGE_INVALID",
      httpStatus: 401,
      message: "Verification session is invalid or expired. Please start again.",
    };
  }

  if (
    userObjectId &&
    (!existing.userId || existing.userId.toString() !== userObjectId.toString())
  ) {
    return {
      ok: false,
      code: "CHALLENGE_INVALID",
      httpStatus: 401,
      message: "Verification session does not match your account.",
    };
  }

  if (params.requireAuthVerified && !existing.authVerified) {
    return {
      ok: false,
      code: "AUTH_NOT_VERIFIED",
      httpStatus: 403,
      message: "Credentials must be verified before requesting a login OTP resend.",
    };
  }

  if (
    params.expectedTokenVersion !== undefined &&
    params.expectedTokenVersion !== null &&
    existing.tokenVersionSnapshot !== params.expectedTokenVersion
  ) {
    return {
      ok: false,
      code: "TOKEN_VERSION_MISMATCH",
      httpStatus: 401,
      message: "Session state changed. Please start authentication again.",
    };
  }

  if (existing.consumedAt) {
    return {
      ok: false,
      code: "CHALLENGE_CONSUMED",
      httpStatus: 401,
      message: "This verification code has already been used. Please start again.",
    };
  }

  if (existing.invalidatedAt) {
    return {
      ok: false,
      code: "CHALLENGE_EXPIRED",
      httpStatus: 401,
      message: "This verification session was superseded. Please start again.",
    };
  }

  if (existing.lockedAt || existing.attempts >= existing.maxAttempts) {
    return {
      ok: false,
      code: "CHALLENGE_LOCKED",
      httpStatus: 423,
      message: "Too many incorrect OTP attempts. Please start again.",
    };
  }

  if (now.getTime() - existing.createdAt.getTime() > CHALLENGE_SESSION_MAX_AGE_MS) {
    return {
      ok: false,
      code: "CHALLENGE_EXPIRED",
      httpStatus: 401,
      message: "Verification session has expired. Please start again.",
    };
  }

  if (existing.resendCount >= existing.maxResends) {
    return {
      ok: false,
      code: "MAX_RESENDS_EXCEEDED",
      httpStatus: 429,
      message: "Maximum resend limit reached. Please start a new verification request.",
    };
  }

  const elapsedSinceLastSend = now.getTime() - existing.lastSentAt.getTime();
  if (elapsedSinceLastSend < OTP_RESEND_COOLDOWN_MS) {
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil((OTP_RESEND_COOLDOWN_MS - elapsedSinceLastSend) / 1000),
    );
    return {
      ok: false,
      code: "RESEND_COOLDOWN",
      httpStatus: 429,
      message: `Please wait ${retryAfterSeconds} seconds before requesting another OTP.`,
      retryAfterSeconds,
    };
  }

  const quotaResult = await enforceIssuanceQuotas({
    purpose: params.purpose,
    normalizedEmail,
    ip: params.ip,
    now,
  });
  if (!quotaResult.ok) {
    return {
      ok: false,
      code: "RATE_LIMITED",
      httpStatus: 429,
      message: `Too many verification requests. Please wait ${quotaResult.retryAfterSeconds} seconds before trying again.`,
      retryAfterSeconds: quotaResult.retryAfterSeconds,
    };
  }

  const cooldownCheck = await touchPersistentCooldownBucket({
    key: `cooldown:${params.purpose}:${normalizedEmail}`,
    cooldownMs: OTP_RESEND_COOLDOWN_MS,
    now,
    enforceCooldown: true,
  });
  if (!cooldownCheck.allowed) {
    return {
      ok: false,
      code: "RESEND_COOLDOWN",
      httpStatus: 429,
      message: `Please wait ${cooldownCheck.retryAfterSeconds} seconds before requesting another OTP.`,
      retryAfterSeconds: cooldownCheck.retryAfterSeconds,
    };
  }

  const isDecoy = Boolean(existing.isDecoy);
  const newChallengeId = generateChallengeId();
  const newChallengeNonce = generateChallengeNonce();
  const newOtpCode = generateOtpCode();
  const newOtpHash = isDecoy
    ? computeOtpHmac({
        purpose: params.purpose,
        normalizedEmail,
        challengeId: newChallengeId,
        challengeNonce: newChallengeNonce,
        otp: generateChallengeNonce(),
      })
    : computeOtpHmac({
        purpose: params.purpose,
        normalizedEmail,
        challengeId: newChallengeId,
        challengeNonce: newChallengeNonce,
        otp: newOtpCode,
      });

  const expiresAt = new Date(now.getTime() + ttlMs);
  const cleanupAt = new Date(now.getTime() + CHALLENGE_RETENTION_MS);
  const purposePhrase = PURPOSE_EMAIL_PHRASES[params.purpose];
  const emailPayloadSpec = otpEmailPayload(newOtpCode, purposePhrase);
  const encryptedPayload = isDecoy
    ? null
    : encryptOutboxPayload({
        to: normalizedEmail,
        toName: params.toName?.trim() || normalizedEmail,
        templateId: emailPayloadSpec.templateId || env.MSG91_TEMPLATE_OTP,
        variables: emailPayloadSpec.variables,
      });

  await ensureOtpCollectionsInitialized();

  const cutoff = new Date(now.getTime() - OTP_RESEND_COOLDOWN_MS);
  const txResult = await runWithOptionalTransaction(undefined, async (session) => {
    const invalidatedOld = await OtpChallenge.findOneAndUpdate(
      {
        _id: existing._id,
        purpose: params.purpose,
        consumedAt: null,
        invalidatedAt: null,
        lockedAt: null,
        resendCount: { $lt: existing.maxResends },
        lastSentAt: { $lte: cutoff },
      },
      { $set: { invalidatedAt: now } },
      { new: true, session },
    );

    if (!invalidatedOld) {
      return null;
    }

    await suppressPendingOutboxesForChallenges([existing.challengeId], now, session);

    const newChallenge = new OtpChallenge({
      challengeId: newChallengeId,
      email: normalizedEmail,
      purpose: params.purpose,
      otpHash: newOtpHash,
      challengeNonce: newChallengeNonce,
      isDecoy,
      authVerified: existing.authVerified,
      userId: existing.userId ?? null,
      tokenVersionSnapshot: existing.tokenVersionSnapshot ?? null,
      pendingData: existing.pendingData ?? null,
      attempts: 0,
      maxAttempts: existing.maxAttempts,
      resendCount: existing.resendCount + 1,
      maxResends: existing.maxResends,
      lastSentAt: now,
      lastAttemptAt: null,
      expiresAt,
      consumedAt: null,
      lockedAt: null,
      invalidatedAt: null,
      outboxId: null,
      deliveryStatus: isDecoy ? "suppressed" : "pending",
      cleanupAt,
    });

    const outboxDoc = await createOutboxDocument(
      {
        challengeId: newChallengeId,
        purpose: params.purpose,
        status: isDecoy ? "suppressed" : "pending",
        encryptedPayload,
        now,
      },
      session,
    );

    newChallenge.outboxId = outboxDoc.outboxId;
    await newChallenge.save({ session });

    return {
      challengeId: newChallenge.challengeId,
      outboxId: outboxDoc.outboxId,
    };
  });

  if (!txResult) {
    return {
      ok: false,
      code: "RESEND_COOLDOWN",
      httpStatus: 429,
      message: "Please wait before requesting another verification code.",
    };
  }

  if (!isDecoy) {
    nudgeEmailOutboxWorker();
  }

  return {
    ok: true,
    challengeId: txResult.challengeId,
    outboxId: txResult.outboxId,
    expiresAt,
    expiresInSeconds: Math.round(ttlMs / 1000),
    resendAfterSeconds: Math.round(OTP_RESEND_COOLDOWN_MS / 1000),
  };
};

/**
 * Verifies a 6-digit OTP in Node.js via timing-safe HMAC comparison, enforcing
 * attempt limits, explicit expiry, purpose/email/user binding, and atomic single-use CAS.
 */
export const verifyChallengeOtp = async (
  params: VerifyChallengeParams,
): Promise<VerifyChallengeResult> => {
  assertOtpCryptoReady();

  const normalizedEmail = normalizeEmail(params.email);
  if (!normalizedEmail) {
    return {
      ok: false,
      code: "INVALID_EMAIL",
      httpStatus: 400,
      message: "A valid email address is required.",
    };
  }

  const submittedOtp = typeof params.otp === "string" ? params.otp.trim() : "";
  if (!/^\d{6}$/.test(submittedOtp)) {
    return {
      ok: false,
      code: "INVALID_OTP",
      httpStatus: 400,
      message: "Please enter a valid 6-digit verification code.",
    };
  }

  const now = params.now ?? new Date();
  const userObjectId = toObjectIdOrNull(params.userId);

  const verifyQuota = await enforceVerifyQuotas({
    purpose: params.purpose,
    normalizedEmail,
    ip: params.ip,
    now,
  });
  if (!verifyQuota.ok) {
    return {
      ok: false,
      code: "RATE_LIMITED",
      httpStatus: 429,
      message: `Too many verification attempts. Please wait ${verifyQuota.retryAfterSeconds} seconds.`,
      retryAfterSeconds: verifyQuota.retryAfterSeconds,
    };
  }

  // Locate target challenge strictly within its purpose + normalizedEmail (+ userId if provided)
  let challenge: IOtpChallenge | null = null;
  if (params.challengeId) {
    challenge = await OtpChallenge.findOne({
      challengeId: params.challengeId,
      purpose: params.purpose,
      email: normalizedEmail,
    });
  } else {
    const query: Record<string, unknown> = {
      purpose: params.purpose,
      email: normalizedEmail,
      consumedAt: null,
      invalidatedAt: null,
    };
    if (userObjectId) {
      query.userId = userObjectId;
    }
    challenge = await OtpChallenge.findOne(query).sort({ createdAt: -1 });
  }

  if (!challenge) {
    return {
      ok: false,
      code: "CHALLENGE_INVALID",
      httpStatus: 401,
      message: "Invalid or expired verification code.",
    };
  }

  if (
    userObjectId &&
    (!challenge.userId || challenge.userId.toString() !== userObjectId.toString())
  ) {
    return {
      ok: false,
      code: "CHALLENGE_INVALID",
      httpStatus: 401,
      message: "Verification code does not match your account.",
    };
  }

  if (params.requireAuthVerified && !challenge.authVerified) {
    return {
      ok: false,
      code: "AUTH_NOT_VERIFIED",
      httpStatus: 403,
      message: "Credentials must be verified first.",
    };
  }

  if (
    params.expectedTokenVersion !== undefined &&
    params.expectedTokenVersion !== null &&
    challenge.tokenVersionSnapshot !== params.expectedTokenVersion
  ) {
    return {
      ok: false,
      code: "TOKEN_VERSION_MISMATCH",
      httpStatus: 401,
      message: "Session has changed. Please start authentication again.",
    };
  }

  if (challenge.consumedAt) {
    return {
      ok: false,
      code: "CHALLENGE_CONSUMED",
      httpStatus: 401,
      message: "This verification code has already been used. Please request a new one.",
    };
  }

  if (challenge.invalidatedAt) {
    return {
      ok: false,
      code: "CHALLENGE_EXPIRED",
      httpStatus: 401,
      message: "This verification code is no longer valid. Please use the latest code sent.",
    };
  }

  if (challenge.lockedAt || challenge.attempts >= challenge.maxAttempts) {
    return {
      ok: false,
      code: "CHALLENGE_LOCKED",
      httpStatus: 423,
      message: "Too many incorrect OTP attempts. Please request a new verification code.",
      attemptsRemaining: 0,
    };
  }

  if (challenge.expiresAt.getTime() <= now.getTime()) {
    return {
      ok: false,
      code: "CHALLENGE_EXPIRED",
      httpStatus: 401,
      message: "Verification code has expired. Please request a new one.",
    };
  }

  // Decoy challenges can NEVER verify true, while still executing symmetric timing-safe HMAC
  // comparison + atomic attempt accounting so decoys lock after 5 attempts like real ones.
  const hmacMatches = verifyOtpHmacDigest(
    {
      purpose: challenge.purpose,
      normalizedEmail: challenge.email,
      challengeId: challenge.challengeId,
      challengeNonce: challenge.challengeNonce,
      otp: submittedOtp,
    },
    challenge.otpHash,
  );

  if (challenge.isDecoy || !hmacMatches) {
    const incremented = await OtpChallenge.findOneAndUpdate(
      {
        _id: challenge._id,
        consumedAt: null,
        invalidatedAt: null,
        lockedAt: null,
        attempts: { $lt: challenge.maxAttempts },
      },
      {
        $inc: { attempts: 1 },
        $set: { lastAttemptAt: now },
      },
      { new: true },
    );

    if (!incremented || incremented.attempts >= incremented.maxAttempts) {
      if (incremented && !incremented.lockedAt) {
        await OtpChallenge.updateOne(
          {
            _id: challenge._id,
            lockedAt: null,
            attempts: { $gte: incremented.maxAttempts },
          },
          { $set: { lockedAt: now } },
        );
      }
      await suppressPendingOutboxesForChallenges([challenge.challengeId], now);
      return {
        ok: false,
        code: "CHALLENGE_LOCKED",
        httpStatus: 423,
        message: "Too many incorrect OTP attempts. Please request a new verification code.",
        attemptsRemaining: 0,
      };
    }

    const attemptsRemaining = Math.max(0, incremented.maxAttempts - incremented.attempts);
    return {
      ok: false,
      code: "INVALID_OTP",
      httpStatus: 401,
      message: "Invalid verification code. Please check and try again.",
      attemptsRemaining,
    };
  }

  // Atomic single-use compare-and-swap inside caller transaction (if any).
  const claimFilter: Record<string, unknown> = {
    _id: challenge._id,
    purpose: params.purpose,
    email: normalizedEmail,
    isDecoy: false,
    consumedAt: null,
    invalidatedAt: null,
    lockedAt: null,
    expiresAt: { $gt: now },
    attempts: { $lt: challenge.maxAttempts },
  };
  if (userObjectId) {
    claimFilter.userId = userObjectId;
  }
  if (params.requireAuthVerified) {
    claimFilter.authVerified = true;
  }
  if (
    params.expectedTokenVersion !== undefined &&
    params.expectedTokenVersion !== null
  ) {
    claimFilter.tokenVersionSnapshot = params.expectedTokenVersion;
  }

  const consumed = await OtpChallenge.findOneAndUpdate(
    claimFilter,
    {
      $set: {
        consumedAt: now,
        lastAttemptAt: now,
      },
    },
    { new: true, session: params.session ?? null },
  );

  if (!consumed) {
    const latest = await OtpChallenge.findById(challenge._id)
      .select("consumedAt invalidatedAt lockedAt attempts maxAttempts expiresAt")
      .lean();
    if (latest?.lockedAt || (latest && latest.attempts >= latest.maxAttempts)) {
      return {
        ok: false,
        code: "CHALLENGE_LOCKED",
        httpStatus: 423,
        message: "Too many incorrect OTP attempts. Please request a new verification code.",
        attemptsRemaining: 0,
      };
    }
    if (latest?.expiresAt && latest.expiresAt.getTime() <= now.getTime()) {
      return {
        ok: false,
        code: "CHALLENGE_EXPIRED",
        httpStatus: 401,
        message: "Verification code has expired. Please request a new one.",
      };
    }
    return {
      ok: false,
      code: "CHALLENGE_CONSUMED",
      httpStatus: 401,
      message: "This verification code has already been used.",
    };
  }

  await suppressPendingOutboxesForChallenges([consumed.challengeId], now, params.session);

  return { ok: true, challenge: consumed };
};

/**
 * Issues a single-use `resetTokenJti` bound to an already-consumed `password_reset` challenge.
 */
export const attachResetTokenJti = async (params: {
  challengeObjectId: Types.ObjectId | string;
  userId: Types.ObjectId | string;
  ttlMs?: number;
  now?: Date;
}): Promise<{ jti: string; expiresAt: Date } | null> => {
  const now = params.now ?? new Date();
  const expiresAt = new Date(now.getTime() + (params.ttlMs ?? RESET_TOKEN_TTL_MS));
  const jti = generateResetJti();

  const updated = await OtpChallenge.findOneAndUpdate(
    {
      _id: params.challengeObjectId,
      purpose: "password_reset",
      isDecoy: false,
      consumedAt: { $ne: null },
      $or: [{ resetTokenJti: null }, { resetTokenJti: { $exists: false } }],
    },
    {
      $set: {
        userId: toObjectIdOrNull(params.userId),
        resetTokenJti: jti,
        resetTokenExpiresAt: expiresAt,
        resetTokenConsumedAt: null,
      },
    },
    { new: true },
  );

  if (!updated) return null;
  return { jti, expiresAt };
};

/**
 * Atomically consumes a single-use `password_reset` `jti` inside an ACID transaction.
 */
export const consumeResetTokenJti = async (params: {
  jti: string;
  email: string;
  userId: Types.ObjectId | string;
  now?: Date;
  session?: ClientSession;
}): Promise<
  | { ok: true; challenge: IOtpChallenge }
  | { ok: false; code: OtpFailureCode; message: string }
> => {
  const normalizedEmail = normalizeEmail(params.email);
  if (!normalizedEmail || !params.jti) {
    return {
      ok: false,
      code: "RESET_TOKEN_INVALID",
      message: "Invalid or expired reset token.",
    };
  }

  const now = params.now ?? new Date();
  const userObjId = toObjectIdOrNull(params.userId);
  const consumed = await OtpChallenge.findOneAndUpdate(
    {
      purpose: "password_reset",
      email: normalizedEmail,
      ...(userObjId ? { userId: userObjId } : {}),
      isDecoy: false,
      consumedAt: { $ne: null },
      resetTokenJti: params.jti,
      resetTokenConsumedAt: null,
      resetTokenExpiresAt: { $gt: now },
    },
    { $set: { resetTokenConsumedAt: now } },
    { new: true, session: params.session ?? null },
  );

  if (!consumed) {
    return {
      ok: false,
      code: "RESET_TOKEN_USED",
      message: "Reset token has expired or has already been used.",
    };
  }

  return { ok: true, challenge: consumed };
};

/**
 * Finds the active (unconsumed, non-invalidated) challenge for user-bound authenticated flows.
 */
export const findLatestActiveChallenge = async (params: {
  purpose: OtpPurpose;
  userId?: string | Types.ObjectId;
  email?: string;
}): Promise<IOtpChallenge | null> => {
  const query: Record<string, unknown> = {
    purpose: params.purpose,
    consumedAt: null,
    invalidatedAt: null,
  };
  if (params.userId) {
    const uid = toObjectIdOrNull(params.userId);
    if (uid) query.userId = uid;
  }
  if (params.email) {
    const norm = normalizeEmail(params.email);
    if (norm) query.email = norm;
  }
  return OtpChallenge.findOne(query).sort({ createdAt: -1 });
};
