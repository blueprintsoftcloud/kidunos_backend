import { ClientSession } from "mongoose";
import { env } from "../config/env";
import {
  hasMsg91EmailConfig,
  Msg91DeliveryError,
  sendMsg91TemplateEmail,
} from "../config/msg91Email";
import {
  AppSetting,
  EmailOutbox,
  OtpChallenge,
  type IEmailOutbox,
} from "../models/mongoose";
import {
  assertOtpCryptoReady,
  decryptOutboxPayload,
  type EncryptedEmailOutboxPayload,
  generateOutboxId,
} from "../utils/otpCrypto";
import logger from "../utils/logger";
import crypto from "crypto";
import os from "os";

export const EMAIL_OUTBOX_KEY_VERSION = 1;
const DEFAULT_CLEANUP_RETENTION_MS = 24 * 60 * 60 * 1000;
const BASE_RETRY_BACKOFF_MS = 2000;
const MAX_RETRY_BACKOFF_MS = 30000;

export const WORKER_INSTANCE_ID = `${os.hostname()}-${process.pid}-${crypto
  .randomBytes(4)
  .toString("hex")}`;

export interface ProcessOutboxBatchOptions {
  workerId?: string;
  now?: Date;
  batchSize?: number;
  staleLockMs?: number;
}

export interface ProcessOutboxBatchSummary {
  claimed: number;
  sent: number;
  retried: number;
  suppressed: number;
  ambiguousTimeout: number;
  failed: number;
}

let pollTimer: NodeJS.Timeout | null = null;
let isShuttingDown = false;
let activeBatchPromise: Promise<ProcessOutboxBatchSummary> | null = null;
let workerRunning = false;

const isObjectRecord = (val: unknown): val is Record<string, unknown> =>
  typeof val === "object" && val !== null;

const TERMINAL_OUTBOX_STATUSES = new Set<IEmailOutbox["status"]>([
  "sent",
  "failed",
  "suppressed",
  "ambiguous_timeout",
]);

/**
 * Ensures non-terminal (`pending` / `processing`) outbox items always have `cleanupAt: null`
 * so MongoDB TTL can never expire queued or in-flight work before reaching a terminal state.
 */
export const createOutboxDocument = async (
  params: {
    challengeId: string;
    purpose: IEmailOutbox["purpose"];
    status: IEmailOutbox["status"];
    encryptedPayload: string | null;
    now: Date;
    maxAttempts?: number;
    cleanupAt?: Date | null;
  },
  session?: ClientSession,
): Promise<IEmailOutbox> => {
  const isTerminal = TERMINAL_OUTBOX_STATUSES.has(params.status);
  const resolvedCleanupAt = isTerminal
    ? (params.cleanupAt ?? new Date(params.now.getTime() + DEFAULT_CLEANUP_RETENTION_MS))
    : null;

  const outboxDoc = new EmailOutbox({
    outboxId: generateOutboxId(),
    status: params.status,
    challengeId: params.challengeId,
    purpose: params.purpose,
    encryptedPayload: params.encryptedPayload,
    encryptionKeyVersion: EMAIL_OUTBOX_KEY_VERSION,
    attempts: 0,
    maxAttempts: params.maxAttempts ?? env.EMAIL_OUTBOX_MAX_ATTEMPTS,
    nextAttemptAt: params.now,
    lockedAt: null,
    lockedBy: null,
    sentAt: null,
    failedAt: null,
    errorCode: null,
    cleanupAt: resolvedCleanupAt,
  });

  await outboxDoc.save(session ? { session } : undefined);
  return outboxDoc;
};

const markOutboxTerminal = async (
  jobId: unknown,
  workerId: string,
  status: "sent" | "failed" | "suppressed" | "ambiguous_timeout",
  fields: {
    sentAt?: Date | null;
    failedAt?: Date | null;
    errorCode?: string | null;
    terminalAt?: Date;
  },
): Promise<boolean> => {
  const terminalTime =
    fields.terminalAt ?? fields.sentAt ?? fields.failedAt ?? new Date();
  const cleanupAt = new Date(terminalTime.getTime() + DEFAULT_CLEANUP_RETENTION_MS);

  const res = await EmailOutbox.updateOne(
    { _id: jobId, status: "processing", lockedBy: workerId },
    {
      $set: {
        status,
        lockedAt: null,
        lockedBy: null,
        sentAt: fields.sentAt ?? null,
        failedAt: fields.failedAt ?? null,
        errorCode: fields.errorCode ?? null,
        cleanupAt,
      },
      $unset: { encryptedPayload: 1 },
    },
  );
  return res.matchedCount > 0;
};

/**
 * Claims one eligible EmailOutbox item atomically, respecting stale lock recovery
 * across multi-worker Passenger processes.
 */
export const claimNextEmailOutboxJob = async (
  options: { workerId?: string; now?: Date; staleLockMs?: number } = {},
): Promise<IEmailOutbox | null> => {
  const workerId = options.workerId || WORKER_INSTANCE_ID;
  const now = options.now ?? new Date();
  const staleLockMs = options.staleLockMs ?? env.EMAIL_OUTBOX_LOCK_TIMEOUT_MS;
  const staleBefore = new Date(now.getTime() - staleLockMs);

  const claimed = await EmailOutbox.findOneAndUpdate(
    {
      $expr: { $lt: ["$attempts", "$maxAttempts"] },
      $or: [
        { status: "pending", nextAttemptAt: { $lte: now } },
        { status: "processing", lockedAt: { $lte: staleBefore } },
      ],
    },
    {
      $set: {
        status: "processing",
        lockedAt: now,
        lockedBy: workerId,
        cleanupAt: null,
      },
      $inc: { attempts: 1 },
    },
    {
      sort: { nextAttemptAt: 1, createdAt: 1 },
      new: true,
    },
  );

  return claimed;
};

const recoverExhaustedStaleJobs = async (
  now: Date,
  staleLockMs: number,
): Promise<void> => {
  const staleBefore = new Date(now.getTime() - staleLockMs);
  const cleanupAt = new Date(now.getTime() + DEFAULT_CLEANUP_RETENTION_MS);
  await EmailOutbox.updateMany(
    {
      status: "processing",
      lockedAt: { $lte: staleBefore },
      $expr: { $gte: ["$attempts", "$maxAttempts"] },
    },
    {
      $set: {
        status: "failed",
        failedAt: now,
        lockedAt: null,
        lockedBy: null,
        errorCode: "STALE_LOCK_EXHAUSTED",
        cleanupAt,
      },
      $unset: { encryptedPayload: 1 },
    },
  );
};

const resolveSenderDisplayName = async (): Promise<string> => {
  try {
    const setting = await AppSetting.findOne({ key: "MSG91_EMAIL_FROM_NAME" })
      .select("value")
      .lean();
    if (setting && typeof setting.value === "string" && setting.value.trim()) {
      return setting.value.trim();
    }
  } catch {
    // Fall back deterministically to validated env setting
  }
  return env.MSG91_EMAIL_FROM_NAME;
};

const processClaimedJob = async (
  job: IEmailOutbox,
  workerId: string,
  now: Date,
): Promise<"sent" | "retried" | "suppressed" | "ambiguous_timeout" | "failed"> => {
  const challenge = await OtpChallenge.findOne({ challengeId: job.challengeId })
    .select(
      "_id challengeId isDecoy consumedAt invalidatedAt lockedAt expiresAt deliveryStatus",
    )
    .lean();

  const currentTime = new Date(Math.max(now.getTime(), Date.now()));

  if (
    !challenge ||
    challenge.isDecoy ||
    challenge.consumedAt ||
    challenge.invalidatedAt ||
    challenge.lockedAt ||
    challenge.expiresAt.getTime() <= currentTime.getTime()
  ) {
    const finalized = await markOutboxTerminal(job._id, workerId, "suppressed", {
      terminalAt: currentTime,
      errorCode: !challenge
        ? "CHALLENGE_MISSING"
        : challenge.isDecoy
          ? "DECOY_SUPPRESSED"
          : "CHALLENGE_INACTIVE",
    });
    if (finalized && challenge && !challenge.isDecoy) {
      await OtpChallenge.updateOne(
        { challengeId: challenge.challengeId, deliveryStatus: "pending" },
        { $set: { deliveryStatus: "suppressed" } },
      );
    }
    return "suppressed";
  }

  if (!job.encryptedPayload) {
    const finalized = await markOutboxTerminal(job._id, workerId, "failed", {
      failedAt: currentTime,
      errorCode: "MISSING_PAYLOAD",
    });
    if (finalized) {
      await OtpChallenge.updateOne(
        { challengeId: job.challengeId },
        { $set: { deliveryStatus: "failed" } },
      );
    }
    return "failed";
  }

  let decrypted: EncryptedEmailOutboxPayload;
  try {
    assertOtpCryptoReady();
    decrypted = decryptOutboxPayload<EncryptedEmailOutboxPayload>(job.encryptedPayload);
  } catch {
    logger.error("[email-outbox] failed to decrypt outbox payload", {
      outboxId: job.outboxId,
      challengeId: job.challengeId,
    });
    const finalized = await markOutboxTerminal(job._id, workerId, "failed", {
      failedAt: currentTime,
      errorCode: "DECRYPT_FAILED",
    });
    if (finalized) {
      await OtpChallenge.updateOne(
        { challengeId: job.challengeId },
        { $set: { deliveryStatus: "failed" } },
      );
    }
    return "failed";
  }

  const templateId = decrypted.templateId || env.MSG91_TEMPLATE_OTP;
  if (!hasMsg91EmailConfig(templateId)) {
    logger.error("[email-outbox] missing MSG91 email configuration for OTP delivery", {
      outboxId: job.outboxId,
      challengeId: job.challengeId,
    });
    const finalized = await markOutboxTerminal(job._id, workerId, "failed", {
      failedAt: currentTime,
      errorCode: "CONFIG_INCOMPLETE",
    });
    if (finalized) {
      await OtpChallenge.updateOne(
        { challengeId: job.challengeId },
        { $set: { deliveryStatus: "failed" } },
      );
    }
    return "failed";
  }

  try {
    const resolvedFromName = await resolveSenderDisplayName();
    await sendMsg91TemplateEmail({
      to: decrypted.to,
      toName: decrypted.toName ?? decrypted.to,
      templateId,
      fromName: resolvedFromName,
      variables: {
        COMPANY_NAME: resolvedFromName,
        ...decrypted.variables,
      },
      throwOnMissingConfig: true,
    });

    const deliveredAt = new Date(Math.max(now.getTime(), Date.now()));
    const finalized = await markOutboxTerminal(job._id, workerId, "sent", {
      sentAt: deliveredAt,
    });
    if (finalized) {
      await OtpChallenge.updateOne(
        { challengeId: job.challengeId },
        { $set: { deliveryStatus: "sent" } },
      );
    }
    logger.info("[email-outbox] OTP email delivered", {
      outboxId: job.outboxId,
      challengeId: job.challengeId,
      purpose: job.purpose,
    });
    return "sent";
  } catch (err: unknown) {
    const finishTime = new Date(Math.max(now.getTime(), Date.now()));
    const deliveryErr = err instanceof Msg91DeliveryError ? err : null;
    const deliveryKind = deliveryErr?.deliveryKind ?? "transient";
    const errorCode =
      deliveryErr?.errorCode ||
      (isObjectRecord(err) && typeof err.code === "string" ? err.code : "DELIVERY_ERROR");

    if (deliveryKind === "ambiguous_timeout") {
      const finalized = await markOutboxTerminal(job._id, workerId, "ambiguous_timeout", {
        failedAt: finishTime,
        errorCode,
      });
      if (finalized) {
        await OtpChallenge.updateOne(
          { challengeId: job.challengeId },
          { $set: { deliveryStatus: "ambiguous_timeout" } },
        );
      }
      logger.warn("[email-outbox] ambiguous provider timeout — no automatic resend", {
        outboxId: job.outboxId,
        challengeId: job.challengeId,
        errorCode,
      });
      return "ambiguous_timeout";
    }

    const canRetryTransient =
      deliveryKind === "transient" &&
      job.attempts < job.maxAttempts &&
      challenge.expiresAt.getTime() > finishTime.getTime();

    if (canRetryTransient) {
      const backoffMs = Math.min(
        MAX_RETRY_BACKOFF_MS,
        BASE_RETRY_BACKOFF_MS * Math.pow(2, Math.max(0, job.attempts - 1)),
      );
      const nextAttemptAt = new Date(finishTime.getTime() + backoffMs);
      if (nextAttemptAt.getTime() < challenge.expiresAt.getTime()) {
        await EmailOutbox.updateOne(
          { _id: job._id, status: "processing", lockedBy: workerId },
          {
            $set: {
              status: "pending",
              nextAttemptAt,
              lockedAt: null,
              lockedBy: null,
              errorCode,
              cleanupAt: null,
            },
          },
        );
        logger.warn("[email-outbox] transient delivery failure — scheduled retry", {
          outboxId: job.outboxId,
          challengeId: job.challengeId,
          attempt: job.attempts,
          maxAttempts: job.maxAttempts,
          errorCode,
        });
        return "retried";
      }
    }

    const finalized = await markOutboxTerminal(job._id, workerId, "failed", {
      failedAt: finishTime,
      errorCode,
    });
    if (finalized) {
      await OtpChallenge.updateOne(
        { challengeId: job.challengeId },
        { $set: { deliveryStatus: "failed" } },
      );
    }
    logger.error("[email-outbox] OTP email permanently failed", {
      outboxId: job.outboxId,
      challengeId: job.challengeId,
      errorCode,
      attempts: job.attempts,
    });
    return "failed";
  }
};

/**
 * Processes up to `batchSize` ready outbox jobs under tracked execution.
 */
export const processOutboxBatchOnce = async (
  options: ProcessOutboxBatchOptions = {},
): Promise<ProcessOutboxBatchSummary> => {
  const workerId = options.workerId || WORKER_INSTANCE_ID;
  const now = options.now ?? new Date();
  const batchSize = options.batchSize ?? env.EMAIL_OUTBOX_BATCH_SIZE;
  const staleLockMs = options.staleLockMs ?? env.EMAIL_OUTBOX_LOCK_TIMEOUT_MS;

  const summary: ProcessOutboxBatchSummary = {
    claimed: 0,
    sent: 0,
    retried: 0,
    suppressed: 0,
    ambiguousTimeout: 0,
    failed: 0,
  };

  await recoverExhaustedStaleJobs(now, staleLockMs);

  for (let i = 0; i < batchSize; i += 1) {
    if (isShuttingDown) break;
    const job = await claimNextEmailOutboxJob({ workerId, now, staleLockMs });
    if (!job) break;

    summary.claimed += 1;
    const outcome = await processClaimedJob(job, workerId, now);
    if (outcome === "sent") summary.sent += 1;
    else if (outcome === "retried") summary.retried += 1;
    else if (outcome === "suppressed") summary.suppressed += 1;
    else if (outcome === "ambiguous_timeout") summary.ambiguousTimeout += 1;
    else summary.failed += 1;
  }

  return summary;
};

const runTrackedPollCycle = (): Promise<ProcessOutboxBatchSummary> => {
  if (activeBatchPromise) return activeBatchPromise;
  activeBatchPromise = processOutboxBatchOnce()
    .catch((err) => {
      logger.error("[email-outbox] worker batch cycle error", {
        message: err instanceof Error ? err.message : String(err),
      });
      return {
        claimed: 0,
        sent: 0,
        retried: 0,
        suppressed: 0,
        ambiguousTimeout: 0,
        failed: 0,
      };
    })
    .finally(() => {
      activeBatchPromise = null;
    });
  return activeBatchPromise;
};

/**
 * Starts the periodic EmailOutbox background worker in non-test environments.
 */
export const startEmailOutboxWorker = (): void => {
  if (workerRunning) return;
  isShuttingDown = false;
  workerRunning = true;

  pollTimer = setInterval(() => {
    if (!isShuttingDown) {
      void runTrackedPollCycle();
    }
  }, env.EMAIL_OUTBOX_POLL_MS);

  if (typeof pollTimer.unref === "function") {
    pollTimer.unref();
  }

  logger.info("[email-outbox] worker started", {
    workerId: WORKER_INSTANCE_ID,
    pollMs: env.EMAIL_OUTBOX_POLL_MS,
    batchSize: env.EMAIL_OUTBOX_BATCH_SIZE,
  });

  void runTrackedPollCycle();
};

/**
 * Triggers immediate outbox processing after transaction commit when running in background mode.
 */
export const nudgeEmailOutboxWorker = (): void => {
  if (env.NODE_ENV === "test" || isShuttingDown) return;
  void runTrackedPollCycle();
};

/**
 * Stops the background worker cleanly and awaits any currently executing job batch
 * so no untracked promises or half-written jobs remain on process shutdown.
 */
export const stopEmailOutboxWorker = async (): Promise<void> => {
  isShuttingDown = true;
  workerRunning = false;
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  if (activeBatchPromise) {
    await activeBatchPromise;
  }
  isShuttingDown = false;
};
