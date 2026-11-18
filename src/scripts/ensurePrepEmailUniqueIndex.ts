/**
 * Transitional Preparation-Window Email Uniqueness Script
 *
 * WHY THIS EXISTS BEFORE MIGRATION 010:
 * `UserSchema` currently defines `email: { type: String, sparse: true }` without
 * `unique: true`, and historical POS/SMS customer records can still contain
 * `email: null` or `email: ""` until Migration 010 backfill and conflict resolution.
 *
 * A full unique index (`{ email: 1 }, { unique: true }`) or a MongoDB sparse unique
 * index (`{ email: 1 }, { unique: true, sparse: true }`) CANNOT be built when multiple
 * historical documents carry `email: null` or `email: ""`, because MongoDB still
 * indexes explicit `null`/`""` fields in sparse indexes (`E11000`).
 *
 * Instead, once preflight verification confirms zero duplicate normalized emails and
 * zero non-normalized non-empty strings across all roles (`CUSTOMER`, `ADMIN`,
 * `STAFF`, `SUPER_ADMIN`), this script creates the transitional partial unique index:
 *
 *   db.users.createIndex(
 *     { email: 1 },
 *     {
 *       name: "uniq_user_nonempty_email_prep",
 *       unique: true,
 *       partialFilterExpression: { email: { $type: "string", $gt: "" } }
 *     }
 *   )
 *
 * TRANSITION TO FINAL ARCHITECTURE (MIGRATION 010 — DO NOT RUN HERE):
 * 1. Keep full unique `phone_1` intact and enforce mandatory normalized emails on all
 *    new Customer SMS signups and POS customer creations (this PR 1 correction).
 * 2. Run `auditCustomerEmailReadiness.ts` and manually backfill/resolve any legacy
 *    `email: null`, empty, malformed, or duplicate rows across all roles.
 * 3. During Migration 010: drop `uniq_user_nonempty_email_prep` and create the final
 *    full unique `{ email: 1 }` index alongside `{ phone: 1 }`.
 *
 * SAFETY GUARANTEES:
 * - Dry-run by default (`--apply` is required to create the index).
 * - Never auto-connects on module import and connects with `autoIndex: false, autoCreate: false`.
 * - Refuses to build the index if duplicates, whitespace-only strings, non-normalized
 *   non-empty strings, or conflicting index definitions exist.
 */

import dotenv from "dotenv";
import path from "path";
import mongoose from "mongoose";
import { User } from "../models/mongoose";
import { normalizeEmail } from "../utils/identity";
import {
  requireOperationalMongoUrl,
  resolveOperationalMongoUrl,
} from "../utils/resolveMongoUri";

export const PREP_EMAIL_UNIQUE_INDEX_NAME = "uniq_user_nonempty_email_prep";
export const PREP_EMAIL_UNIQUE_PARTIAL_FILTER = {
  email: { $type: "string", $gt: "" },
} as const;

export interface EnsurePrepEmailIndexOptions {
  apply?: boolean;
}

export interface PrepEmailIndexResult {
  mode: "dry_run" | "apply";
  status: "eligible" | "already_present" | "applied" | "blocked";
  applied: boolean;
  indexName: string;
  partialFilterExpression: Record<string, unknown>;
  existingIndexes: {
    hasPrepPartialUnique: boolean;
    hasFullUniqueEmail: boolean;
    hasPhoneUnique: boolean;
    conflictingEmailIndexes: string[];
  };
  audit: {
    totalUsers: number;
    nullOrMissingEmails: number;
    emptyStringEmails: number;
    whitespaceOnlyEmails: number;
    nonNormalizedEmails: number;
    malformedEmails: number;
    duplicateNormalizedEmails: number;
  };
  blockers: string[];
  warnings: string[];
  migration010Plan: string;
}

interface MongoIndexSpec {
  name?: string;
  key?: Record<string, unknown>;
  unique?: boolean;
  partialFilterExpression?: Record<string, unknown>;
}

const isExactEmailSingleFieldKey = (key?: Record<string, unknown>): boolean => {
  if (!key) return false;
  const entries = Object.entries(key);
  return entries.length === 1 && entries[0][0] === "email" && entries[0][1] === 1;
};

const isExactPhoneUniqueKey = (key?: Record<string, unknown>): boolean => {
  if (!key) return false;
  const entries = Object.entries(key);
  return entries.length === 1 && entries[0][0] === "phone" && entries[0][1] === 1;
};

const matchesPrepPartialFilter = (expr?: Record<string, unknown>): boolean => {
  if (!expr || typeof expr !== "object") return false;
  const emailFilter = expr.email as Record<string, unknown> | undefined;
  if (!emailFilter || typeof emailFilter !== "object") return false;
  const keys = Object.keys(expr);
  const innerKeys = Object.keys(emailFilter).sort();
  return (
    keys.length === 1 &&
    innerKeys.length === 2 &&
    innerKeys[0] === "$gt" &&
    innerKeys[1] === "$type" &&
    emailFilter.$type === "string" &&
    emailFilter.$gt === ""
  );
};

export const ensurePrepEmailUniqueIndex = async (
  options: EnsurePrepEmailIndexOptions = {},
): Promise<PrepEmailIndexResult> => {
  if (mongoose.connection.readyState !== 1) {
    throw new Error("Mongoose must be connected before inspecting or creating preparation email unique index.");
  }

  const mode = options.apply ? "apply" : "dry_run";
  const indexes = (await User.collection.indexes()) as unknown as MongoIndexSpec[];

  let hasPrepPartialUnique = false;
  let hasFullUniqueEmail = false;
  let hasPhoneUnique = false;
  const conflictingEmailIndexes: string[] = [];

  for (const idx of indexes) {
    const idxName = idx.name ?? "<unnamed>";
    if (isExactPhoneUniqueKey(idx.key) && idx.unique === true) {
      hasPhoneUnique = true;
    }

    const isEmailKey = isExactEmailSingleFieldKey(idx.key);
    const isPrepName = idxName === PREP_EMAIL_UNIQUE_INDEX_NAME;

    if (isEmailKey && idx.unique === true && !idx.partialFilterExpression) {
      hasFullUniqueEmail = true;
      continue;
    }

    if (
      isEmailKey &&
      idx.unique === true &&
      matchesPrepPartialFilter(idx.partialFilterExpression)
    ) {
      hasPrepPartialUnique = true;
      continue;
    }

    if (isPrepName) {
      conflictingEmailIndexes.push(idxName);
    }
  }

  // Scan raw documents read-only without triggering Mongoose hooks.
  const rawUsers = (await User.collection
    .find({}, { projection: { _id: 1, email: 1, role: 1 } })
    .toArray()) as Array<{ _id: mongoose.Types.ObjectId; email?: unknown; role?: unknown }>;

  let nullOrMissingEmails = 0;
  let emptyStringEmails = 0;
  let whitespaceOnlyEmails = 0;
  let nonNormalizedEmails = 0;
  let malformedEmails = 0;

  const normalizedEmailCounts = new Map<string, number>();

  for (const user of rawUsers) {
    if (user.email === undefined || user.email === null) {
      nullOrMissingEmails += 1;
      continue;
    }
    if (typeof user.email !== "string") {
      malformedEmails += 1;
      continue;
    }
    if (user.email === "") {
      emptyStringEmails += 1;
      continue;
    }

    const trimmed = user.email.trim();
    if (trimmed.length === 0) {
      whitespaceOnlyEmails += 1;
      continue;
    }

    const lower = trimmed.toLowerCase();
    if (user.email !== lower) {
      nonNormalizedEmails += 1;
    }

    if (!normalizeEmail(user.email)) {
      malformedEmails += 1;
    }

    normalizedEmailCounts.set(lower, (normalizedEmailCounts.get(lower) ?? 0) + 1);
  }

  let duplicateNormalizedEmails = 0;
  for (const count of normalizedEmailCounts.values()) {
    if (count > 1) {
      duplicateNormalizedEmails += 1;
    }
  }

  const blockers: string[] = [];
  const warnings: string[] = [];

  if (conflictingEmailIndexes.length > 0) {
    blockers.push(
      `Conflicting index definition found under ${conflictingEmailIndexes.join(", ")}. Drop the incompatible index before retrying.`,
    );
  }
  if (duplicateNormalizedEmails > 0) {
    blockers.push(
      `${duplicateNormalizedEmails} duplicate normalized email group(s) exist across users. Resolve via auditCustomerEmailReadiness.ts before building unique index.`,
    );
  }
  if (nonNormalizedEmails > 0) {
    blockers.push(
      `${nonNormalizedEmails} user(s) have non-normalized email strings (uppercase or leading/trailing whitespace). Normalize before building binary partial unique index.`,
    );
  }
  if (whitespaceOnlyEmails > 0) {
    blockers.push(
      `${whitespaceOnlyEmails} user(s) have whitespace-only email strings that would match $gt: "". Clean these records first.`,
    );
  }
  if (malformedEmails > 0) {
    warnings.push(
      `${malformedEmails} user(s) have malformed email format; Migration 010 remediation is still required before Email OTP cutover.`,
    );
  }
  if (!hasPhoneUnique) {
    warnings.push("Unique index on { phone: 1 } was not found on users collection.");
  }

  const migration010Plan =
    `Coexists with full unique phone_1 during PR 1 prep window while allowing historical email: null/"". ` +
    `During Migration 010 (before PR 2 Email OTP cutover): backfill missing emails, resolve conflicts, normalize all emails, ` +
    `drop ${PREP_EMAIL_UNIQUE_INDEX_NAME}, and build full unique { email: 1 }.`;

  if (hasFullUniqueEmail || hasPrepPartialUnique) {
    return {
      mode,
      status: blockers.length > 0 ? "blocked" : "already_present",
      applied: false,
      indexName: PREP_EMAIL_UNIQUE_INDEX_NAME,
      partialFilterExpression: { ...PREP_EMAIL_UNIQUE_PARTIAL_FILTER },
      existingIndexes: {
        hasPrepPartialUnique,
        hasFullUniqueEmail,
        hasPhoneUnique,
        conflictingEmailIndexes,
      },
      audit: {
        totalUsers: rawUsers.length,
        nullOrMissingEmails,
        emptyStringEmails,
        whitespaceOnlyEmails,
        nonNormalizedEmails,
        malformedEmails,
        duplicateNormalizedEmails,
      },
      blockers,
      warnings,
      migration010Plan,
    };
  }

  if (blockers.length > 0) {
    return {
      mode,
      status: "blocked",
      applied: false,
      indexName: PREP_EMAIL_UNIQUE_INDEX_NAME,
      partialFilterExpression: { ...PREP_EMAIL_UNIQUE_PARTIAL_FILTER },
      existingIndexes: {
        hasPrepPartialUnique,
        hasFullUniqueEmail,
        hasPhoneUnique,
        conflictingEmailIndexes,
      },
      audit: {
        totalUsers: rawUsers.length,
        nullOrMissingEmails,
        emptyStringEmails,
        whitespaceOnlyEmails,
        nonNormalizedEmails,
        malformedEmails,
        duplicateNormalizedEmails,
      },
      blockers,
      warnings,
      migration010Plan,
    };
  }

  if (!options.apply) {
    return {
      mode,
      status: "eligible",
      applied: false,
      indexName: PREP_EMAIL_UNIQUE_INDEX_NAME,
      partialFilterExpression: { ...PREP_EMAIL_UNIQUE_PARTIAL_FILTER },
      existingIndexes: {
        hasPrepPartialUnique,
        hasFullUniqueEmail,
        hasPhoneUnique,
        conflictingEmailIndexes,
      },
      audit: {
        totalUsers: rawUsers.length,
        nullOrMissingEmails,
        emptyStringEmails,
        whitespaceOnlyEmails,
        nonNormalizedEmails,
        malformedEmails,
        duplicateNormalizedEmails,
      },
      blockers,
      warnings,
      migration010Plan,
    };
  }

  await User.collection.createIndex(
    { email: 1 },
    {
      name: PREP_EMAIL_UNIQUE_INDEX_NAME,
      unique: true,
      partialFilterExpression: { email: { $type: "string", $gt: "" } },
    },
  );

  return {
    mode,
    status: "applied",
    applied: true,
    indexName: PREP_EMAIL_UNIQUE_INDEX_NAME,
    partialFilterExpression: { ...PREP_EMAIL_UNIQUE_PARTIAL_FILTER },
    existingIndexes: {
      hasPrepPartialUnique: true,
      hasFullUniqueEmail,
      hasPhoneUnique,
      conflictingEmailIndexes,
    },
    audit: {
      totalUsers: rawUsers.length,
      nullOrMissingEmails,
      emptyStringEmails,
      whitespaceOnlyEmails,
      nonNormalizedEmails,
      malformedEmails,
      duplicateNormalizedEmails,
    },
    blockers,
    warnings,
    migration010Plan,
  };
};

export const formatPrepEmailIndexSummary = (report: PrepEmailIndexResult): string => {
  const lines: string[] = [
    "=== Storra PR 1 Transitional Email Unique Index Preflight ===",
    `Mode                       : ${report.mode}`,
    `Status                     : ${report.status}`,
    `Index Applied This Run     : ${report.applied ? "YES" : "NO"}`,
    `Target Index               : ${report.indexName} (partial: email string > "")`,
    `Prep Partial Index Exists  : ${report.existingIndexes.hasPrepPartialUnique ? "YES" : "NO"}`,
    `Full Unique Email Exists   : ${report.existingIndexes.hasFullUniqueEmail ? "YES" : "NO"}`,
    `Phone Unique Index Exists  : ${report.existingIndexes.hasPhoneUnique ? "YES" : "NO"}`,
    "",
    "--- User Email Compatibility Audit ---",
    `Total Users                : ${report.audit.totalUsers}`,
    `Null / Missing Emails      : ${report.audit.nullOrMissingEmails} (allowed by partial filter)`,
    `Empty "" Emails            : ${report.audit.emptyStringEmails} (allowed by partial filter)`,
    `Whitespace-only Emails     : ${report.audit.whitespaceOnlyEmails}`,
    `Non-normalized Emails      : ${report.audit.nonNormalizedEmails}`,
    `Malformed Emails (warn)    : ${report.audit.malformedEmails}`,
    `Duplicate Normalized Groups: ${report.audit.duplicateNormalizedEmails}`,
  ];

  if (report.blockers.length > 0) {
    lines.push("", "--- Blockers (Aborted) ---");
    for (const b of report.blockers) lines.push(`  - ${b}`);
  }

  if (report.warnings.length > 0) {
    lines.push("", "--- Warnings ---");
    for (const w of report.warnings) lines.push(`  - ${w}`);
  }

  lines.push("", `Migration 010 Note: ${report.migration010Plan}`);
  return lines.join("\n");
};

export const resolvePrepEmailIndexUrl = (
  envObj: NodeJS.ProcessEnv = process.env,
): string => resolveOperationalMongoUrl(envObj);

const runCli = async () => {
  dotenv.config({ path: path.resolve(process.cwd(), ".env") });
  dotenv.config({ path: path.resolve(__dirname, "../../.env") });
  const args = process.argv.slice(2);
  const apply = args.includes("--apply");
  const jsonMode = args.includes("--json");

  let databaseUrl: string;
  try {
    databaseUrl = requireOperationalMongoUrl("the prep email unique index script");
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
    return;
  }

  await mongoose.connect(databaseUrl, {
    autoIndex: false,
    autoCreate: false,
  });

  try {
    const result = await ensurePrepEmailUniqueIndex({ apply });
    if (jsonMode) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(formatPrepEmailIndexSummary(result));
    }

    if (result.status === "blocked") {
      process.exitCode = 1;
    }
  } finally {
    await mongoose.disconnect();
  }
};

if (require.main === module) {
  runCli().catch((err) => {
    console.error("Prep email unique index script failed:", err instanceof Error ? err.message : err);
    process.exit(1);
  });
}

