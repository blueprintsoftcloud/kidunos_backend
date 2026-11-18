/**
 * Shared identity validation and canonicalization helpers.
 *
 * Keeps customer email and mobile validation consistent across Zod schemas,
 * Express controllers, POS workflows, and readiness scripts.
 */

export const EMAIL_FORMAT_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}$/;
export const CANONICAL_INDIA_PHONE_REGEX = /^[6-9][0-9]{9}$/;
export const CANONICAL_UAE_PHONE_REGEX = /^5[0-9]{8}$/;

/** Escapes special regular-expression characters before exact regex matching. */
export const escapeRegex = (val: string): string =>
  val.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Validates, trims, and lowercases an email address.
 * Returns `null` when missing, non-string, empty, or malformed.
 */
export const normalizeEmail = (raw: unknown): string | null => {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 254) return null;
  if (!EMAIL_FORMAT_REGEX.test(trimmed)) return null;

  const [localPart, domain] = trimmed.split("@");
  if (!localPart || !domain || localPart.length > 64) return null;
  if (localPart.startsWith(".") || localPart.endsWith(".") || localPart.includes("..")) {
    return null;
  }
  if (domain.startsWith(".") || domain.endsWith(".") || domain.includes("..")) {
    return null;
  }
  if (
    domain
      .split(".")
      .some((label) => !label || label.startsWith("-") || label.endsWith("-"))
  ) {
    return null;
  }

  return trimmed.toLowerCase();
};

/**
 * Validates a strict 10-digit Indian mobile number (`^[6-9][0-9]{9}$`) after trimming.
 * Returns the canonical 10-digit string or `null` if missing/invalid.
 */
export const normalizeStrictIndianPhone = (raw: unknown): string | null => {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!CANONICAL_INDIA_PHONE_REGEX.test(trimmed)) return null;
  return trimmed;
};

/**
 * Normalizes Indian 10-digit mobile numbers across 91/+91/0/raw/spaced forms.
 * Returns the canonical 10-digit string or `null` if invalid.
 */
export const normalizeIndianMobile = (raw: unknown): string | null => {
  if (typeof raw !== "string" && typeof raw !== "number") return null;
  const cleaned = String(raw).replace(/[\s\-()+]/g, "");
  if (!/^\d+$/.test(cleaned)) return null;
  if (/^[6-9][0-9]{9}$/.test(cleaned)) return cleaned;
  if (/^91([6-9][0-9]{9})$/.test(cleaned)) return cleaned.slice(2);
  if (/^0([6-9][0-9]{9})$/.test(cleaned)) return cleaned.slice(1);
  return null;
};

/** Validates the canonical nine-digit UAE mobile number stored for customer accounts. */
export const normalizeStrictUaePhone = (raw: unknown): string | null => {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  return CANONICAL_UAE_PHONE_REGEX.test(trimmed) ? trimmed : null;
};

/** Normalizes UAE mobile numbers from local, +971, 971, or leading-0 formats. */
export const normalizeUaeMobile = (raw: unknown): string | null => {
  if (typeof raw !== "string" && typeof raw !== "number") return null;
  const cleaned = String(raw).replace(/[\s\-()+]/g, "");
  if (!/^\d+$/.test(cleaned)) return null;
  if (CANONICAL_UAE_PHONE_REGEX.test(cleaned)) return cleaned;
  if (/^0(5[0-9]{8})$/.test(cleaned)) return cleaned.slice(1);
  if (/^971(5[0-9]{8})$/.test(cleaned)) return cleaned.slice(3);
  if (/^00971(5[0-9]{8})$/.test(cleaned)) return cleaned.slice(5);
  return null;
};
