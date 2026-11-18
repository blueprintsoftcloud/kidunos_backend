// src/config/env.ts
// Validates ALL environment variables at startup using Zod.
// The app will exit immediately with a clear error if any required variable is missing.
// Import { env } instead of process.env throughout the app.

import { z } from "zod";
import dotenv from "dotenv";
import path from "path";
import {
  findSecretReusePairs,
  isPublishedSampleSecret,
  isStrongProductionOtpHmacSecret,
  isStrongProductionOutboxEncKey,
  isWeakSecret,
} from "./secretValidation";

// Load .env from process.cwd() or fallback to relative paths when not under test
if (process.env.NODE_ENV !== "test") {
  dotenv.config();
  dotenv.config({ path: path.resolve(process.cwd(), ".env") });
  dotenv.config({ path: path.resolve(__dirname, "../../.env") });
  dotenv.config({ path: path.resolve(__dirname, "../.env") });
}

export const envSchema = z
  .object({
    NODE_ENV: z
      .enum(["development", "production", "test"])
      .default("development"),
    PORT: z.string().default("5000"),
    ALLOWED_ORIGINS: z.string().default("http://localhost:5173"),
    STOREFRONT_URL: z.string().url().default("http://localhost:5173"),
    TRUST_PROXY_HOPS: z.coerce.number().int().min(0).max(10).default(1),

    // Database — MONGO_URL is the only var Mongoose reads (see config/database.ts).
    MONGO_URL: z.string().min(1, "MONGO_URL is required"),

    // JWT & Auth Secrets (never fallback to hardcoded defaults)
    JWT_SECRET: z.string().min(1, "JWT_SECRET is required"),
    REFRESH_TOKEN_SECRET: z
      .string()
      .min(1, "REFRESH_TOKEN_SECRET is required"),
    OTP_HMAC_SECRET: z.string().default(""),
    OUTBOX_ENC_KEY: z.string().default(""),

    // PR 2 Feature Flags & EmailOutbox Worker Configuration
    CUSTOMER_EMAIL_OTP_ENABLED: z.enum(["true", "false"]).default("false"),
    EMAIL_OUTBOX_POLL_MS: z.coerce.number().int().min(100).max(60000).default(2000),
    EMAIL_OUTBOX_BATCH_SIZE: z.coerce.number().int().min(1).max(100).default(10),
    EMAIL_OUTBOX_LOCK_TIMEOUT_MS: z.coerce.number().int().min(5000).max(600000).default(60000),
    EMAIL_OUTBOX_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(10).default(3),

    // System alert recipient — the health monitor's "[System Alert]" emails go here.
    // (Previously also the SMTP account address; email now sends via MSG91, see below.)
    EMAIL_USER: z.string().default("unaiznoushad105@gmail.com"),

    // Storage Provider: "r2" (Cloudflare R2 - recommended) or "cloudinary"
    STORAGE_PROVIDER: z.enum(["r2", "cloudinary"]).default("cloudinary"),

    // Cloudflare R2 (10GB free, unlimited zero-cost egress)
    R2_ACCOUNT_ID: z.string().default(""),
    R2_ACCESS_KEY_ID: z.string().default(""),
    R2_SECRET_ACCESS_KEY: z.string().default(""),
    R2_BUCKET_NAME: z.string().default(""),
    R2_PUBLIC_DOMAIN: z.string().default(""),

    // Cloudinary (legacy)
    CLOUDINARY_CLOUD_NAME: z.string().default(""),
    CLOUDINARY_API_KEY: z.string().default(""),
    CLOUDINARY_API_SECRET: z.string().default(""),

    // Nomod — server-side hosted checkout
    NOMOD_API_KEY: z.string().default(""),

    // Legacy Razorpay credentials retained only to verify historical in-flight orders.
    RAZORPAY_KEY_ID: z.string().default(""),
    RAZORPAY_KEY_SECRET: z.string().default(""),
    RAZORPAY_WEBHOOK_SECRET: z.string().default(""),

    // MSG91 Mobile OTP (SMS widget) — MSG91_AUTH_KEY is the account-wide key, also
    // used to authenticate the Email API calls below.
    MSG91_AUTH_KEY: z.string().default(""),
    MSG91_TOKEN_AUTH: z.string().default(""),
    MSG91_WIDGET_ID: z.string().default(""),

    // MSG91 Email API — replaces the old SMTP/nodemailer transport for every
    // transactional email (OTP, order confirmation, order status, system alerts).
    // MSG91_EMAIL_DOMAIN must be a domain verified in MSG91's Email dashboard, and
    // MSG91_EMAIL_FROM must be an address on that domain. Each MSG91_TEMPLATE_*
    // is the id of a template created in MSG91's dashboard (Email > Templates) with
    // {{variable}} placeholders matching what config/mailer.ts's payload builders
    // send — see that file's per-template variable list. Left blank, non-OTP sendEmail()
    // logs a warning and no-ops instead of failing the request; OTP delivery fails explicitly.
    MSG91_EMAIL_DOMAIN: z.string().default(""),
    MSG91_EMAIL_FROM: z.string().default(""),
    MSG91_EMAIL_FROM_NAME: z.string().default("blueprint_crm"),
    MSG91_TEMPLATE_OTP: z.string().default(""),
    MSG91_TEMPLATE_ORDER_CONFIRMATION: z.string().default(""),
    MSG91_TEMPLATE_ORDER_STATUS: z.string().default(""),
    MSG91_TEMPLATE_HEALTH_ALERT: z.string().default(""),

    // Shipping
    WAREHOUSE_LAT: z.string().default("9.9312"),
    WAREHOUSE_LNG: z.string().default("76.2673"),

    // Background job / inventory alert config
    LOW_STOCK_THRESHOLD: z.string().default("5"),

    // Backup / disaster recovery (see docs/DISASTER_RECOVERY.md)
    BACKUP_DIR: z.string().default("./backups"),
    BACKUP_RETENTION_COUNT: z.string().default("14"),

    // Legacy optional field — current double-submit CSRF uses CSPRNG per-session tokens
    // rather than signing with CSRF_SECRET. Kept optional for backward env compatibility.
    CSRF_SECRET: z.string().default(""),
  })
  .superRefine((data, ctx) => {
    if (data.NODE_ENV !== "production") return;

    if (!data.NOMOD_API_KEY.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["NOMOD_API_KEY"],
        message: "NOMOD_API_KEY is required for production checkout.",
      });
    }

    if (!data.STOREFRONT_URL.startsWith("https://")) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["STOREFRONT_URL"],
        message: "Production STOREFRONT_URL must use HTTPS.",
      });
    }

    if (
      data.JWT_SECRET.trim().length < 32 ||
      isWeakSecret(data.JWT_SECRET) ||
      isPublishedSampleSecret(data.JWT_SECRET)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["JWT_SECRET"],
        message: isPublishedSampleSecret(data.JWT_SECRET)
          ? "Production JWT_SECRET must not use a published example secret."
          : "Production JWT_SECRET must be a strong non-default secret of at least 32 characters.",
      });
    }

    if (
      data.REFRESH_TOKEN_SECRET.trim().length < 32 ||
      isWeakSecret(data.REFRESH_TOKEN_SECRET) ||
      isPublishedSampleSecret(data.REFRESH_TOKEN_SECRET)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["REFRESH_TOKEN_SECRET"],
        message: isPublishedSampleSecret(data.REFRESH_TOKEN_SECRET)
          ? "Production REFRESH_TOKEN_SECRET must not use a published example secret."
          : "Production REFRESH_TOKEN_SECRET must be a strong non-default secret of at least 32 characters.",
      });
    }

    if (data.JWT_SECRET.trim() === data.REFRESH_TOKEN_SECRET.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["REFRESH_TOKEN_SECRET"],
        message: "Production REFRESH_TOKEN_SECRET must differ from JWT_SECRET.",
      });
    }

    if (!isStrongProductionOtpHmacSecret(data.OTP_HMAC_SECRET)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["OTP_HMAC_SECRET"],
        message: isPublishedSampleSecret(data.OTP_HMAC_SECRET)
          ? "Production OTP_HMAC_SECRET must not use a published example secret; generate an independent key via openssl rand -hex 32."
          : "Production OTP_HMAC_SECRET must be a cryptographically random 256-bit key (e.g., 64+ hex characters via openssl rand -hex 32 or padded base64 via openssl rand -base64 32), not a weak or human-readable passphrase.",
      });
    }

    if (!isStrongProductionOutboxEncKey(data.OUTBOX_ENC_KEY)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["OUTBOX_ENC_KEY"],
        message: isPublishedSampleSecret(data.OUTBOX_ENC_KEY)
          ? "Production OUTBOX_ENC_KEY must not use a published example secret; generate an independent key via openssl rand -hex 32."
          : "Production OUTBOX_ENC_KEY must be a cryptographically random 64-character hex string (32-byte AES-256-GCM key).",
      });
    }

    const reusePairs = findSecretReusePairs({
      JWT_SECRET: data.JWT_SECRET,
      REFRESH_TOKEN_SECRET: data.REFRESH_TOKEN_SECRET,
      OTP_HMAC_SECRET: data.OTP_HMAC_SECRET,
      OUTBOX_ENC_KEY: data.OUTBOX_ENC_KEY,
    });
    for (const [first, second] of reusePairs) {
      if (first === "JWT_SECRET" && second === "REFRESH_TOKEN_SECRET") {
        // Already emitted exact legacy issue message above when raw strings matched;
        // catch encoded/byte-level reuse cleanly without duplicating on identical string.
        if (data.JWT_SECRET.trim() !== data.REFRESH_TOKEN_SECRET.trim()) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["REFRESH_TOKEN_SECRET"],
            message: "Production REFRESH_TOKEN_SECRET must differ from JWT_SECRET.",
          });
        }
        continue;
      }
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: [second],
        message: `Production ${second} must differ from ${first}.`,
      });
    }
  });

export type EnvConfig = z.infer<typeof envSchema>;

export const parseEnv = (rawEnv: NodeJS.ProcessEnv = process.env): EnvConfig => {
  const parsed = envSchema.safeParse(rawEnv);
  if (!parsed.success) {
    const errors = parsed.error.flatten().fieldErrors;
    throw new Error(`Invalid or missing environment variables: ${JSON.stringify(errors)}`);
  }
  return parsed.data;
};

let resolvedEnv: EnvConfig;
try {
  resolvedEnv = parseEnv(process.env);
} catch (err) {
  const message = err instanceof Error ? err.message : "Invalid environment configuration";
  console.error("\n❌ Environment validation failed:", message, "\nCreate/fix .env based on .env.example and restart.\n");
  process.exit(1);
}

export const env = resolvedEnv;
