import crypto from "crypto";

const KNOWN_INSECURE_SECRETS = new Set([
  "mysecretkey123",
  "mysecretkey123_refresh",
  "dev_csrf_secret_change_me",
  "secret",
  "changeme",
  "change_me",
  "password",
  "123456",
]);

const WEAK_SECRET_SUBSTRINGS = [
  "mysecretkey123",
  "change_me",
  "changeme",
  "passphrase",
  "placeholder",
  "replace_with",
  "your_secret",
];

// SHA-256 digests of the raw 32-byte keys and canonical lowercase UTF-8 strings
// previously published as examples in backend/.env.example. Stored solely as
// one-way digests so production validation rejects copied sample secrets and
// their hex/Base64/Base64url encodings without embedding sample keys in source.
const PUBLISHED_SAMPLE_KEY_SHA256 = new Set([
  "8de9e608d749d6fcf9e8a430a292099c319dc8192f934324eb787bd3c5a4dbb6",
  "17bbe075b9d505dbf55bde4bc7a71ebb671bc976b7bf052bebb4951e760aecd4",
  "9ca4692da27c020690490e7b448a90238941a8056e603b3736089da944df6f25",
  "deca4c3327a1ef7bc278f4340a3dc863572fb5b623790fdf0b3fc82b8cca5a6b",
]);

export type CoreSecretName =
  | "JWT_SECRET"
  | "REFRESH_TOKEN_SECRET"
  | "OTP_HMAC_SECRET"
  | "OUTBOX_ENC_KEY";

export const isWeakSecret = (val: string): boolean => {
  const normalized = val.trim().toLowerCase();
  if (!normalized || KNOWN_INSECURE_SECRETS.has(normalized)) return true;
  return WEAK_SECRET_SUBSTRINGS.some((sub) => normalized.includes(sub));
};

const computeShannonEntropyBitsPerByte = (buf: Buffer): number => {
  if (buf.length === 0) return 0;
  const counts = new Map<number, number>();
  for (const byte of buf) {
    counts.set(byte, (counts.get(byte) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / buf.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
};

const hasRepeatingPeriod = (buf: Buffer): boolean => {
  for (const period of [1, 2, 4, 8, 16]) {
    if (buf.length <= period) continue;
    let matches = true;
    for (let i = period; i < buf.length; i += 1) {
      if (buf[i] !== buf[i % period]) {
        matches = false;
        break;
      }
    }
    if (matches) return true;
  }
  return false;
};

const hasConstantByteStride = (buf: Buffer): boolean => {
  if (buf.length < 4) return true;
  const strideSet = new Set<number>();
  for (let i = 1; i < buf.length; i += 1) {
    strideSet.add((buf[i] - buf[i - 1] + 256) % 256);
    if (strideSet.size > 1) return false;
  }
  return true;
};

export const hasHighCryptographicEntropy = (buf: Buffer): boolean => {
  if (buf.length < 32) return false;
  const uniqueBytes = new Set(buf);
  if (uniqueBytes.size < 16) return false;
  if (computeShannonEntropyBitsPerByte(buf) < 4.0) return false;
  if (hasRepeatingPeriod(buf)) return false;
  if (hasConstantByteStride(buf)) return false;
  // Prevents base64-encoded plain ASCII text (bytes strictly < 0x80) from passing as CSPRNG bytes.
  if (!buf.some((b) => b >= 0x80)) return false;
  return true;
};

/**
 * Validates production `OTP_HMAC_SECRET`:
 * Requires high-entropy encoded 256-bit key material (either >= 64 even-length hex chars
 * e.g. `openssl rand -hex 32`, or canonical padded Base64 decoding to >= 32 random bytes
 * e.g. `openssl rand -base64 32`). Human-readable passphrases and repeating strings fail closed.
 */
export const isStrongProductionOtpHmacSecret = (raw: string): boolean => {
  const s = raw.trim();
  if (!s || isWeakSecret(s) || isPublishedSampleSecret(s)) return false;

  if (/^[0-9a-fA-F]{64,}$/.test(s) && s.length % 2 === 0) {
    const decoded = Buffer.from(s, "hex");
    return hasHighCryptographicEntropy(decoded);
  }

  if (/^[A-Za-z0-9+/]{43,}={1,2}$/.test(s) && s.length % 4 === 0) {
    const decoded = Buffer.from(s, "base64");
    if (decoded.toString("base64") !== s) return false;
    return hasHighCryptographicEntropy(decoded);
  }

  return false;
};

/**
 * Validates production `OUTBOX_ENC_KEY`:
 * Must be a high-entropy 64-character hex string decoding to 32 random AES-256-GCM key bytes.
 */
export const isStrongProductionOutboxEncKey = (raw: string): boolean => {
  const s = raw.trim();
  if (!/^[0-9a-fA-F]{64}$/.test(s) || isWeakSecret(s) || isPublishedSampleSecret(s)) {
    return false;
  }
  const decoded = Buffer.from(s, "hex");
  return hasHighCryptographicEntropy(decoded);
};

const hashSha256Hex = (buf: Buffer): string =>
  crypto.createHash("sha256").update(buf).digest("hex");

const extractKeyFingerprints = (raw: string): Set<string> => {
  const fingerprints = new Set<string>();
  const s = raw.trim();
  if (!s) return fingerprints;

  fingerprints.add(Buffer.from(s, "utf8").toString("hex"));

  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0 && s.length >= 16) {
    fingerprints.add(Buffer.from(s, "hex").toString("hex"));
  }

  if (/^[A-Za-z0-9+/]+={0,2}$/.test(s) && s.length % 4 === 0 && s.length >= 16) {
    const decoded = Buffer.from(s, "base64");
    if (decoded.toString("base64") === s) {
      fingerprints.add(decoded.toString("hex"));
    }
  }

  if (/^[A-Za-z0-9_-]{16,}$/.test(s)) {
    const decoded = Buffer.from(s, "base64url");
    if (decoded.toString("base64url") === s) {
      fingerprints.add(decoded.toString("hex"));
    }
  }

  return fingerprints;
};

/**
 * Returns `true` when `val` matches any published `.env.example` cryptographic sample
 * key across raw UTF-8, lowercase/uppercase hex, Base64 (padded or unpadded), or Base64url.
 */
export const isPublishedSampleSecret = (val: string): boolean => {
  const s = val.trim();
  if (!s) return false;

  const candidates: Buffer[] = [
    Buffer.from(s, "utf8"),
    Buffer.from(s.toLowerCase(), "utf8"),
  ];

  for (const fpHex of extractKeyFingerprints(s)) {
    candidates.push(Buffer.from(fpHex, "hex"));
  }

  if (/^[A-Za-z0-9+/]{16,}$/.test(s) && s.length % 4 !== 1) {
    const padded = s.padEnd(s.length + ((4 - (s.length % 4)) % 4), "=");
    const decoded = Buffer.from(padded, "base64");
    if (decoded.toString("base64").replace(/=+$/, "") === s) {
      candidates.push(decoded);
    }
  }

  return candidates.some((buf) => PUBLISHED_SAMPLE_KEY_SHA256.has(hashSha256Hex(buf)));
};

/**
 * Returns every pair of configured secrets whose raw UTF-8 or decoded cryptographic
 * key bytes collide across `(JWT_SECRET, REFRESH_TOKEN_SECRET, OTP_HMAC_SECRET, OUTBOX_ENC_KEY)`.
 */
export const findSecretReusePairs = (
  secrets: Record<CoreSecretName, string>,
): Array<[CoreSecretName, CoreSecretName]> => {
  const names: CoreSecretName[] = [
    "JWT_SECRET",
    "REFRESH_TOKEN_SECRET",
    "OTP_HMAC_SECRET",
    "OUTBOX_ENC_KEY",
  ];
  const map = new Map<CoreSecretName, Set<string>>();
  for (const name of names) {
    map.set(name, extractKeyFingerprints(secrets[name] ?? ""));
  }

  const pairs: Array<[CoreSecretName, CoreSecretName]> = [];
  for (let i = 0; i < names.length; i += 1) {
    const a = names[i];
    const setA = map.get(a)!;
    if (setA.size === 0) continue;
    for (let j = i + 1; j < names.length; j += 1) {
      const b = names[j];
      const setB = map.get(b)!;
      if (setB.size === 0) continue;
      for (const fp of setA) {
        if (setB.has(fp)) {
          pairs.push([a, b]);
          break;
        }
      }
    }
  }
  return pairs;
};

