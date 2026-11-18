import crypto from "crypto";
import jwt from "jsonwebtoken";
import { env } from "../config/env";
import {
  findSecretReusePairs,
  isPublishedSampleSecret,
  isStrongProductionOtpHmacSecret,
  isStrongProductionOutboxEncKey,
  isWeakSecret,
} from "../config/secretValidation";
import type { OtpPurpose } from "../models/mongoose";

export const ENCRYPTION_KEY_VERSION = 1;
const CIPHER_PREFIX = "v1";

/**
 * Validates that OTP HMAC verification and EmailOutbox payload encryption keys
 * are configured, syntactically valid, sufficiently random in production, and
 * pairwise distinct across JWT/Refresh/HMAC/Encryption secrets.
 * Fails closed whenever OTP infrastructure is invoked without valid keys.
 */
export const assertOtpCryptoReady = (): { hmacSecret: string; encKey: Buffer } => {
  const hmacSecret = (env.OTP_HMAC_SECRET || "").trim();
  if (!hmacSecret) {
    throw new Error("OTP_HMAC_SECRET must be configured for OTP hashing and verification.");
  }

  if (env.NODE_ENV === "production") {
    if (isPublishedSampleSecret(hmacSecret)) {
      throw new Error("Production OTP_HMAC_SECRET must not use a published example secret.");
    }
    if (!isStrongProductionOtpHmacSecret(hmacSecret)) {
      throw new Error(
        "Production OTP_HMAC_SECRET must be a cryptographically random 256-bit key, not a weak or human-readable passphrase.",
      );
    }
  } else if (isWeakSecret(hmacSecret)) {
    throw new Error("OTP_HMAC_SECRET must not use a known weak or default value.");
  }

  const encKeyHex = (env.OUTBOX_ENC_KEY || "").trim();
  if (!/^[0-9a-fA-F]{64}$/.test(encKeyHex)) {
    throw new Error(
      "OUTBOX_ENC_KEY must be a 64-character hex string (32-byte AES-256-GCM key).",
    );
  }

  if (env.NODE_ENV === "production") {
    if (isPublishedSampleSecret(encKeyHex)) {
      throw new Error("Production OUTBOX_ENC_KEY must not use a published example secret.");
    }
    if (!isStrongProductionOutboxEncKey(encKeyHex)) {
      throw new Error(
        "Production OUTBOX_ENC_KEY must be a cryptographically random 64-character hex key (32 bytes).",
      );
    }
  }

  const reusePairs = findSecretReusePairs({
    JWT_SECRET: env.JWT_SECRET || "",
    REFRESH_TOKEN_SECRET: env.REFRESH_TOKEN_SECRET || "",
    OTP_HMAC_SECRET: hmacSecret,
    OUTBOX_ENC_KEY: encKeyHex,
  });

  if (reusePairs.length > 0) {
    const hasEncHmac = reusePairs.some(
      ([a, b]) =>
        (a === "OTP_HMAC_SECRET" && b === "OUTBOX_ENC_KEY") ||
        (a === "OUTBOX_ENC_KEY" && b === "OTP_HMAC_SECRET"),
    );
    if (hasEncHmac) {
      throw new Error("OUTBOX_ENC_KEY must NOT reuse OTP_HMAC_SECRET.");
    }
    const [first, second] = reusePairs[0];
    throw new Error(`${second} must NOT reuse ${first}.`);
  }

  const encKey = Buffer.from(encKeyHex, "hex");
  if (encKey.length !== 32) {
    throw new Error("OUTBOX_ENC_KEY must decode to 32 bytes.");
  }

  return { hmacSecret, encKey };
};

export const generateChallengeId = (): string =>
  crypto.randomBytes(24).toString("base64url");

export const generateChallengeNonce = (): string =>
  crypto.randomBytes(24).toString("hex");

export const generateOutboxId = (): string =>
  `obx_${crypto.randomBytes(18).toString("base64url")}`;

export const generateResetJti = (): string => crypto.randomUUID();

const canonicalOtpFrame = (params: {
  purpose: OtpPurpose | string;
  normalizedEmail: string;
  challengeId: string;
  challengeNonce: string;
  otp: string;
}): string => {
  const fields = [
    "storra-otp-v1",
    String(params.purpose),
    params.normalizedEmail.trim().toLowerCase(),
    params.challengeId,
    params.challengeNonce,
    params.otp,
  ];
  return fields
    .map((value) => `${Buffer.byteLength(value, "utf8")}:${value}`)
    .join("|");
};

/**
 * Computes HMAC-SHA256 bound to `(purpose, normalizedEmail, challengeId, challengeNonce, otp)`.
 */
export const computeOtpHmac = (params: {
  purpose: OtpPurpose | string;
  normalizedEmail: string;
  challengeId: string;
  challengeNonce: string;
  otp: string;
}): string => {
  const { hmacSecret } = assertOtpCryptoReady();
  const payload = canonicalOtpFrame(params);
  return crypto.createHmac("sha256", hmacSecret).update(payload, "utf8").digest("hex");
};

/**
 * Computes expected HMAC and compares with stored digest in constant time.
 */
export const verifyOtpHmacDigest = (
  params: {
    purpose: OtpPurpose | string;
    normalizedEmail: string;
    challengeId: string;
    challengeNonce: string;
    otp: string;
  },
  storedHexDigest: string | null | undefined,
): boolean => {
  if (!storedHexDigest || typeof storedHexDigest !== "string") return false;
  if (!/^[0-9a-fA-F]{64}$/.test(storedHexDigest)) return false;

  const expectedHex = computeOtpHmac(params);
  const expectedBuf = Buffer.from(expectedHex, "hex");
  const storedBuf = Buffer.from(storedHexDigest, "hex");
  if (expectedBuf.length !== storedBuf.length || expectedBuf.length !== 32) {
    return false;
  }

  return crypto.timingSafeEqual(expectedBuf, storedBuf);
};

export interface EncryptedEmailOutboxPayload {
  to: string;
  toName?: string;
  templateId: string;
  variables: Record<string, string>;
}

/**
 * Encrypts sensitive EmailOutbox template payload using AES-256-GCM with an authenticated tag.
 */
export const encryptOutboxPayload = (payload: EncryptedEmailOutboxPayload): string => {
  const { encKey } = assertOtpCryptoReady();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encKey, iv);
  cipher.setAAD(Buffer.from(`${CIPHER_PREFIX}:email_outbox`, "utf8"));

  const serialized = JSON.stringify(payload);
  const encrypted = Buffer.concat([cipher.update(serialized, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return `${CIPHER_PREFIX}:${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted.toString("hex")}`;
};

/**
 * Decrypts and authenticates an EmailOutbox encrypted payload string.
 */
export const decryptOutboxPayload = <T = EncryptedEmailOutboxPayload>(token: string): T => {
  if (!token || typeof token !== "string") {
    throw new Error("Encrypted outbox payload is empty.");
  }

  const parts = token.split(":");
  if (parts.length !== 4 || parts[0] !== CIPHER_PREFIX) {
    throw new Error("Unsupported or malformed encrypted outbox payload format.");
  }

  const [, ivHex, authTagHex, cipherHex] = parts;
  if (
    !/^[0-9a-fA-F]{24}$/.test(ivHex) ||
    !/^[0-9a-fA-F]{32}$/.test(authTagHex) ||
    !/^[0-9a-fA-F]+$/.test(cipherHex)
  ) {
    throw new Error("Corrupted encrypted outbox payload encoding.");
  }

  const { encKey } = assertOtpCryptoReady();
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");
  const ciphertext = Buffer.from(cipherHex, "hex");

  const decipher = crypto.createDecipheriv("aes-256-gcm", encKey, iv);
  decipher.setAAD(Buffer.from(`${CIPHER_PREFIX}:email_outbox`, "utf8"));
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  return JSON.parse(decrypted) as T;
};

export interface AdminLoginChallengeClaims {
  typ: "admin_login_challenge";
  challengeId: string;
  userId: string;
  email: string;
  tokenVersionSnapshot: number;
}

const getAdminChallengeSecret = (): Buffer =>
  crypto
    .createHmac("sha256", env.JWT_SECRET)
    .update("storra:admin_login_challenge:v1", "utf8")
    .digest();

export const signAdminLoginChallengeCookie = (params: {
  challengeId: string;
  userId: string;
  email: string;
  tokenVersionSnapshot: number;
}): string => {
  const payload: AdminLoginChallengeClaims = {
    typ: "admin_login_challenge",
    challengeId: params.challengeId,
    userId: params.userId,
    email: params.email.trim().toLowerCase(),
    tokenVersionSnapshot: params.tokenVersionSnapshot,
  };
  return jwt.sign(payload, getAdminChallengeSecret(), { expiresIn: "15m" });
};

export const verifyAdminLoginChallengeCookie = (
  token: string | undefined | null,
): AdminLoginChallengeClaims | null => {
  if (!token || typeof token !== "string") return null;
  try {
    const decoded = jwt.verify(token, getAdminChallengeSecret()) as Partial<AdminLoginChallengeClaims>;
    if (
      decoded.typ !== "admin_login_challenge" ||
      typeof decoded.challengeId !== "string" ||
      !decoded.challengeId ||
      typeof decoded.userId !== "string" ||
      !decoded.userId ||
      typeof decoded.email !== "string" ||
      !decoded.email ||
      typeof decoded.tokenVersionSnapshot !== "number" ||
      !Number.isInteger(decoded.tokenVersionSnapshot) ||
      decoded.tokenVersionSnapshot < 0
    ) {
      return null;
    }
    return {
      typ: "admin_login_challenge",
      challengeId: decoded.challengeId,
      userId: decoded.userId,
      email: decoded.email.trim().toLowerCase(),
      tokenVersionSnapshot: decoded.tokenVersionSnapshot,
    };
  } catch {
    return null;
  }
};

