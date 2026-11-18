/**
 * Strictly read-only pre-migration & Email OTP cutover readiness audit script.
 *
 * SAFETY GUARANTEES:
 * - Never writes, updates, deletes, or auto-merges any database documents.
 * - Never creates or syncs MongoDB indexes (`autoIndex: false`, `autoCreate: false`).
 * - Never auto-connects on module import (only executes when invoked as a CLI).
 *
 * Usage:
 *   npx tsx src/scripts/auditCustomerEmailReadiness.ts [--json] [--strict-cutover]
 */

import dotenv from "dotenv";
import path from "path";
import mongoose from "mongoose";
import { Address, Order, OrderArchive, PaymentLog, User } from "../models/mongoose";
import {
  CANONICAL_UAE_PHONE_REGEX,
  EMAIL_FORMAT_REGEX,
  normalizeUaeMobile,
} from "../utils/identity";
import { requireOperationalMongoUrl } from "../utils/resolveMongoUri";

export { CANONICAL_UAE_PHONE_REGEX, EMAIL_FORMAT_REGEX };

export interface UserReferenceCounts {
  ordersCount: number;
  archivedOrdersCount: number;
  paymentLogsCount: number;
  addressesCount: number;
}

export interface AuditedUserRef {
  id: string;
  username: string;
  role: string;
  rawEmail: string | null;
  normalizedEmail: string | null;
  rawPhone: string | null;
  normalizedPhone: string | null;
  isActive: boolean;
  isVerified: boolean;
  emailVerifiedAt: string | null;
  references: UserReferenceCounts;
}

export interface DuplicateGroup<T = AuditedUserRef> {
  key: string;
  count: number;
  roles: string[];
  users: T[];
}

export interface InvalidPhoneEntry extends AuditedUserRef {
  reason: "MISSING_OR_EMPTY" | "NEEDS_NORMALIZATION" | "INVALID_FORMAT";
}

export interface CustomerEmailReadinessReport {
  generatedAt: string;
  readOnlyVerified: true;
  totals: {
    totalUsers: number;
    byRole: Record<string, number>;
  };
  customerEmailAudit: {
    missingOrEmptyEmails: AuditedUserRef[];
    malformedEmails: AuditedUserRef[];
    nonNormalizedEmails: AuditedUserRef[];
    unverifiedEmails: AuditedUserRef[];
    posActivationCandidates: AuditedUserRef[];
    historicalPasswords: {
      count: number;
      note: string;
      sampleUserIds: string[];
    };
  };
  privilegedEmailAudit: {
    missingOrEmptyEmails: AuditedUserRef[];
    malformedEmails: AuditedUserRef[];
    nonNormalizedEmails: AuditedUserRef[];
  };
  crossRoleConflicts: {
    duplicateNormalizedEmails: DuplicateGroup[];
    duplicatePhones: DuplicateGroup[];
  };
  phoneAudit: {
    invalidPhones: InvalidPhoneEntry[];
  };
  blockerCounts: {
    missingOrEmptyCustomerEmails: number;
    malformedCustomerEmails: number;
    nonNormalizedCustomerEmails: number;
    malformedPrivilegedEmails: number;
    nonNormalizedPrivilegedEmails: number;
    duplicateNormalizedEmails: number;
    duplicatePhones: number;
    invalidPhones: number;
  };
  readinessCounts: {
    unverifiedCustomerEmails: number;
    posActivationCandidates: number;
    historicalCustomerPasswords: number;
  };
  hasBlockers: boolean;
  isCutoverReady: boolean;
}

interface RawUserDoc {
  _id: mongoose.Types.ObjectId;
  username?: unknown;
  email?: unknown;
  phone?: unknown;
  password?: unknown;
  role?: unknown;
  isActive?: unknown;
  isVerified?: unknown;
  emailVerifiedAt?: unknown;
}

export const normalizePhoneForAudit = normalizeUaeMobile;

const emptyRefs = (): UserReferenceCounts => ({
  ordersCount: 0,
  archivedOrdersCount: 0,
  paymentLogsCount: 0,
  addressesCount: 0,
});

const aggregateCountsByUserId = async (
  collection: mongoose.Collection,
  objectIds: mongoose.Types.ObjectId[],
): Promise<Map<string, number>> => {
  const counts = new Map<string, number>();
  if (objectIds.length === 0) return counts;

  const rows = await collection
    .aggregate<{ _id: mongoose.Types.ObjectId; count: number }>([
      { $match: { userId: { $in: objectIds } } },
      { $group: { _id: "$userId", count: { $sum: 1 } } },
    ])
    .toArray();

  for (const row of rows) {
    if (row._id) {
      counts.set(String(row._id), row.count);
    }
  }
  return counts;
};

export const generateCustomerEmailReadinessReport = async (): Promise<CustomerEmailReadinessReport> => {
  if (mongoose.connection.readyState !== 1) {
    throw new Error("Mongoose must be connected before running customer email readiness audit.");
  }

  // Strictly read raw user documents directly from collection (no Mongoose hooks or writes).
  const rawUsers = (await User.collection
    .find(
      {},
      {
        projection: {
          _id: 1,
          username: 1,
          email: 1,
          phone: 1,
          password: 1,
          role: 1,
          isActive: 1,
          isVerified: 1,
          emailVerifiedAt: 1,
        },
      },
    )
    .toArray()) as unknown as RawUserDoc[];

  const byRole: Record<string, number> = {};
  const emailGroups = new Map<string, RawUserDoc[]>();
  const phoneGroups = new Map<string, RawUserDoc[]>();

  const affectedObjectIdMap = new Map<string, mongoose.Types.ObjectId>();
  const markAffected = (u: RawUserDoc) => {
    affectedObjectIdMap.set(String(u._id), u._id);
  };

  const missingOrEmptyCustomerDocs: RawUserDoc[] = [];
  const malformedCustomerDocs: RawUserDoc[] = [];
  const nonNormalizedCustomerDocs: RawUserDoc[] = [];
  const unverifiedCustomerDocs: RawUserDoc[] = [];
  const posCandidateDocs: RawUserDoc[] = [];
  const historicalPasswordIds: string[] = [];

  const missingOrEmptyPrivDocs: RawUserDoc[] = [];
  const malformedPrivDocs: RawUserDoc[] = [];
  const nonNormalizedPrivDocs: RawUserDoc[] = [];

  const invalidPhoneEntriesRaw: Array<{ doc: RawUserDoc; reason: InvalidPhoneEntry["reason"] }> = [];

  for (const user of rawUsers) {
    const role = typeof user.role === "string" && user.role ? user.role : "UNKNOWN";
    byRole[role] = (byRole[role] ?? 0) + 1;

    const rawEmail = typeof user.email === "string" ? user.email : null;
    const trimmedEmail = rawEmail !== null ? rawEmail.trim() : null;
    const normalizedEmail =
      trimmedEmail && trimmedEmail.length > 0 ? trimmedEmail.toLowerCase() : null;

    if (normalizedEmail) {
      const list = emailGroups.get(normalizedEmail) ?? [];
      list.push(user);
      emailGroups.set(normalizedEmail, list);
    }

    const rawPhone = typeof user.phone === "string" ? user.phone : user.phone != null ? String(user.phone) : null;
    const canonicalPhone = normalizePhoneForAudit(rawPhone);
    const phoneKey =
      canonicalPhone ??
      (rawPhone !== null && rawPhone.trim().length > 0 ? `RAW:${rawPhone.trim()}` : null);

    if (phoneKey) {
      const list = phoneGroups.get(phoneKey) ?? [];
      list.push(user);
      phoneGroups.set(phoneKey, list);
    }

    if (rawPhone === null || rawPhone.trim().length === 0) {
      invalidPhoneEntriesRaw.push({ doc: user, reason: "MISSING_OR_EMPTY" });
      markAffected(user);
    } else if (!CANONICAL_UAE_PHONE_REGEX.test(rawPhone)) {
      invalidPhoneEntriesRaw.push({
        doc: user,
        reason: canonicalPhone ? "NEEDS_NORMALIZATION" : "INVALID_FORMAT",
      });
      markAffected(user);
    }

    const hasVerifiedEmailAt = user.emailVerifiedAt instanceof Date || (typeof user.emailVerifiedAt === "string" && user.emailVerifiedAt.length > 0);

    if (role === "CUSTOMER") {
      if (user.email === undefined || user.email === null || (trimmedEmail !== null && trimmedEmail.length === 0) || typeof user.email !== "string") {
        missingOrEmptyCustomerDocs.push(user);
        markAffected(user);
      } else if (!EMAIL_FORMAT_REGEX.test(trimmedEmail!)) {
        malformedCustomerDocs.push(user);
        markAffected(user);
      } else if (user.email !== normalizedEmail) {
        nonNormalizedCustomerDocs.push(user);
        markAffected(user);
      }

      if (!hasVerifiedEmailAt) {
        unverifiedCustomerDocs.push(user);
        markAffected(user);
        if (user.isVerified === true) {
          posCandidateDocs.push(user);
        }
      }

      if (typeof user.password === "string" && user.password.length > 0) {
        historicalPasswordIds.push(String(user._id));
      }
    } else {
      if (user.email === undefined || user.email === null || (trimmedEmail !== null && trimmedEmail.length === 0) || typeof user.email !== "string") {
        missingOrEmptyPrivDocs.push(user);
        markAffected(user);
      } else if (!EMAIL_FORMAT_REGEX.test(trimmedEmail!)) {
        malformedPrivDocs.push(user);
        markAffected(user);
      } else if (user.email !== normalizedEmail) {
        nonNormalizedPrivDocs.push(user);
        markAffected(user);
      }
    }
  }

  const duplicateEmailGroupsRaw: Array<{ key: string; docs: RawUserDoc[] }> = [];
  for (const [key, docs] of emailGroups.entries()) {
    if (docs.length > 1) {
      duplicateEmailGroupsRaw.push({ key, docs });
      docs.forEach(markAffected);
    }
  }

  const duplicatePhoneGroupsRaw: Array<{ key: string; docs: RawUserDoc[] }> = [];
  for (const [key, docs] of phoneGroups.entries()) {
    if (docs.length > 1) {
      duplicatePhoneGroupsRaw.push({ key, docs });
      docs.forEach(markAffected);
    }
  }

  const affectedObjectIds = Array.from(affectedObjectIdMap.values());

  const [orderCounts, archivedOrderCounts, paymentLogCounts, addressCounts] =
    await Promise.all([
      aggregateCountsByUserId(Order.collection, affectedObjectIds),
      aggregateCountsByUserId(OrderArchive.collection, affectedObjectIds),
      aggregateCountsByUserId(PaymentLog.collection, affectedObjectIds),
      aggregateCountsByUserId(Address.collection, affectedObjectIds),
    ]);

  const toAuditedRef = (u: RawUserDoc): AuditedUserRef => {
    const id = String(u._id);
    const rawEmail = typeof u.email === "string" ? u.email : null;
    const normalizedEmail =
      rawEmail && rawEmail.trim().length > 0 ? rawEmail.trim().toLowerCase() : null;
    const rawPhone =
      typeof u.phone === "string" ? u.phone : u.phone != null ? String(u.phone) : null;
    const verifiedDate =
      u.emailVerifiedAt instanceof Date
        ? u.emailVerifiedAt.toISOString()
        : typeof u.emailVerifiedAt === "string" && u.emailVerifiedAt.length > 0
          ? u.emailVerifiedAt
          : null;

    return {
      id,
      username: typeof u.username === "string" ? u.username : "",
      role: typeof u.role === "string" ? u.role : "UNKNOWN",
      rawEmail,
      normalizedEmail,
      rawPhone,
      normalizedPhone: normalizePhoneForAudit(rawPhone),
      isActive: u.isActive !== false,
      isVerified: u.isVerified === true,
      emailVerifiedAt: verifiedDate,
      references:
        affectedObjectIdMap.has(id)
          ? {
              ordersCount: orderCounts.get(id) ?? 0,
              archivedOrdersCount: archivedOrderCounts.get(id) ?? 0,
              paymentLogsCount: paymentLogCounts.get(id) ?? 0,
              addressesCount: addressCounts.get(id) ?? 0,
            }
          : emptyRefs(),
    };
  };

  const duplicateNormalizedEmails: DuplicateGroup[] = duplicateEmailGroupsRaw.map((g) => ({
    key: g.key,
    count: g.docs.length,
    roles: Array.from(new Set(g.docs.map((d) => String(d.role ?? "UNKNOWN")))),
    users: g.docs.map(toAuditedRef),
  }));

  const duplicatePhones: DuplicateGroup[] = duplicatePhoneGroupsRaw.map((g) => ({
    key: g.key.startsWith("RAW:") ? g.key.slice(4) : g.key,
    count: g.docs.length,
    roles: Array.from(new Set(g.docs.map((d) => String(d.role ?? "UNKNOWN")))),
    users: g.docs.map(toAuditedRef),
  }));

  const invalidPhones: InvalidPhoneEntry[] = invalidPhoneEntriesRaw.map(({ doc, reason }) => ({
    ...toAuditedRef(doc),
    reason,
  }));

  const missingOrEmptyEmails = missingOrEmptyCustomerDocs.map(toAuditedRef);
  const malformedEmails = malformedCustomerDocs.map(toAuditedRef);
  const nonNormalizedEmails = nonNormalizedCustomerDocs.map(toAuditedRef);
  const unverifiedEmails = unverifiedCustomerDocs.map(toAuditedRef);
  const posActivationCandidates = posCandidateDocs.map(toAuditedRef);

  const malformedPrivEmails = malformedPrivDocs.map(toAuditedRef);
  const nonNormalizedPrivEmails = nonNormalizedPrivDocs.map(toAuditedRef);

  const blockerCounts = {
    missingOrEmptyCustomerEmails: missingOrEmptyEmails.length,
    malformedCustomerEmails: malformedEmails.length,
    nonNormalizedCustomerEmails: nonNormalizedEmails.length,
    malformedPrivilegedEmails: malformedPrivEmails.length,
    nonNormalizedPrivilegedEmails: nonNormalizedPrivEmails.length,
    duplicateNormalizedEmails: duplicateNormalizedEmails.length,
    duplicatePhones: duplicatePhones.length,
    invalidPhones: invalidPhones.length,
  };

  const hasBlockers =
    blockerCounts.missingOrEmptyCustomerEmails > 0 ||
    blockerCounts.malformedCustomerEmails > 0 ||
    blockerCounts.nonNormalizedCustomerEmails > 0 ||
    blockerCounts.malformedPrivilegedEmails > 0 ||
    blockerCounts.nonNormalizedPrivilegedEmails > 0 ||
    blockerCounts.duplicateNormalizedEmails > 0 ||
    blockerCounts.duplicatePhones > 0 ||
    blockerCounts.invalidPhones > 0;

  const isCutoverReady = !hasBlockers && unverifiedEmails.length === 0;

  return {
    generatedAt: new Date().toISOString(),
    readOnlyVerified: true,
    totals: {
      totalUsers: rawUsers.length,
      byRole,
    },
    customerEmailAudit: {
      missingOrEmptyEmails,
      malformedEmails,
      nonNormalizedEmails,
      unverifiedEmails,
      posActivationCandidates,
      historicalPasswords: {
        count: historicalPasswordIds.length,
        note: "Preserved in MongoDB but disabled/ignored at all login endpoints.",
        sampleUserIds: historicalPasswordIds.slice(0, 50),
      },
    },
    privilegedEmailAudit: {
      missingOrEmptyEmails: missingOrEmptyPrivDocs.map(toAuditedRef),
      malformedEmails: malformedPrivEmails,
      nonNormalizedEmails: nonNormalizedPrivEmails,
    },
    crossRoleConflicts: {
      duplicateNormalizedEmails,
      duplicatePhones,
    },
    phoneAudit: {
      invalidPhones,
    },
    blockerCounts,
    readinessCounts: {
      unverifiedCustomerEmails: unverifiedEmails.length,
      posActivationCandidates: posActivationCandidates.length,
      historicalCustomerPasswords: historicalPasswordIds.length,
    },
    hasBlockers,
    isCutoverReady,
  };
};

export const formatReadinessSummary = (report: CustomerEmailReadinessReport): string => {
  const lines: string[] = [
    "=== Storra Customer Email Readiness Audit (Strictly Read-Only) ===",
    `Generated At : ${report.generatedAt}`,
    `Total Users  : ${report.totals.totalUsers} (${Object.entries(report.totals.byRole)
      .map(([role, count]) => `${role}=${count}`)
      .join(", ")})`,
    "",
    "-- Migration / Uniqueness Blockers --",
    `  Missing/Null/Empty CUSTOMER emails : ${report.blockerCounts.missingOrEmptyCustomerEmails}`,
    `  Malformed CUSTOMER emails          : ${report.blockerCounts.malformedCustomerEmails}`,
    `  Non-normalized CUSTOMER emails     : ${report.blockerCounts.nonNormalizedCustomerEmails}`,
    `  Malformed privileged emails        : ${report.blockerCounts.malformedPrivilegedEmails}`,
    `  Non-normalized privileged emails   : ${report.blockerCounts.nonNormalizedPrivilegedEmails}`,
    `  Duplicate normalized emails (all)  : ${report.blockerCounts.duplicateNormalizedEmails}`,
    `  Duplicate phones (all roles)       : ${report.blockerCounts.duplicatePhones}`,
    `  Invalid / un-normalized phones     : ${report.blockerCounts.invalidPhones}`,
    `  Has Schema/Index Blockers          : ${report.hasBlockers ? "YES (NON-ZERO EXIT)" : "NO"}`,
    "",
    "-- Customer Verification & Activation Tracking --",
    `  CUSTOMER emailVerifiedAt === null  : ${report.readinessCounts.unverifiedCustomerEmails}`,
    `  POS walk-in activation candidates  : ${report.readinessCounts.posActivationCandidates}`,
    `  Historical CUSTOMER passwords      : ${report.readinessCounts.historicalCustomerPasswords} (${report.customerEmailAudit.historicalPasswords.note})`,
    `  Full Email-OTP Cutover Ready       : ${report.isCutoverReady ? "YES" : "NO"}`,
  ];

  if (report.crossRoleConflicts.duplicateNormalizedEmails.length > 0) {
    lines.push("", "-- Duplicate Normalized Emails (Manual Review Required; NO Auto-Merge) --");
    for (const grp of report.crossRoleConflicts.duplicateNormalizedEmails) {
      lines.push(`  [${grp.key}] count=${grp.count} roles=${grp.roles.join(",")}`);
      for (const u of grp.users) {
        lines.push(
          `    - id=${u.id} role=${u.role} phone=${u.rawPhone ?? "<null>"} rawEmail=${u.rawEmail ?? "<null>"} orders=${u.references.ordersCount} archivedOrders=${u.references.archivedOrdersCount} payments=${u.references.paymentLogsCount} addresses=${u.references.addressesCount}`,
        );
      }
    }
  }

  if (report.crossRoleConflicts.duplicatePhones.length > 0) {
    lines.push("", "-- Duplicate Phones (Manual Review Required; NO Auto-Merge) --");
    for (const grp of report.crossRoleConflicts.duplicatePhones) {
      lines.push(`  [${grp.key}] count=${grp.count} roles=${grp.roles.join(",")}`);
      for (const u of grp.users) {
        lines.push(
          `    - id=${u.id} role=${u.role} rawEmail=${u.rawEmail ?? "<null>"} rawPhone=${u.rawPhone ?? "<null>"} orders=${u.references.ordersCount} archivedOrders=${u.references.archivedOrdersCount} payments=${u.references.paymentLogsCount} addresses=${u.references.addressesCount}`,
        );
      }
    }
  }

  return lines.join("\n");
};

const runCli = async () => {
  dotenv.config({ path: path.resolve(process.cwd(), ".env") });
  dotenv.config({ path: path.resolve(__dirname, "../../.env") });

  const args = new Set(process.argv.slice(2));
  const jsonOnly = args.has("--json");
  const strictCutover = args.has("--strict-cutover");

  let mongoUrl: string;
  try {
    mongoUrl = requireOperationalMongoUrl("the customer email readiness audit");
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(2);
    return;
  }

  try {
    await mongoose.connect(mongoUrl, {
      autoIndex: false,
      autoCreate: false,
    });

    const report = await generateCustomerEmailReadinessReport();

    if (jsonOnly) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(formatReadinessSummary(report));
      console.log("\n-- Full JSON Report --");
      console.log(JSON.stringify(report, null, 2));
    }

    const shouldFail = report.hasBlockers || (strictCutover && !report.isCutoverReady);
    await mongoose.disconnect();
    process.exit(shouldFail ? 1 : 0);
  } catch (err) {
    console.error("Customer email readiness audit failed:", err);
    try {
      await mongoose.disconnect();
    } catch {}
    process.exit(2);
  }
};

if (require.main === module) {
  void runCli();
}
