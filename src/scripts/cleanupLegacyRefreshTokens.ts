/**
 * Controlled one-time pre-PR-1 legacy refresh-token & session cleanup procedure.
 *
 * WHY THIS REPLACES ANY 64-HEX REGEX FILTER:
 * Both pre-PR-1 plaintext refresh tokens (`crypto.randomBytes(32).toString("hex")`)
 * and PR 1 SHA-256 refresh-token digests (`sha256(tokenValue)`) are 64 lowercase
 * hexadecimal characters (`/^[a-f0-9]{64}$/`). String inspection alone cannot tell them
 * apart once PR 1 workers start issuing sessions.
 *
 * CONTROLLED EXECUTION WINDOW:
 * Execute ONCE during the PR 1 deploy maintenance window AFTER stopping pre-PR-1 workers
 * and BEFORE starting PR 1 workers (while 100% of stored refresh tokens are legacy
 * plaintext values and 0 PR 1 SHA-256 digests exist):
 *   1. Stop existing Node.js / Passenger workers (maintenance mode)
 *   2. Dry-run preview : npm run auth:cleanup-legacy-tokens
 *   3. Apply cleanup   : npm run auth:cleanup-legacy-tokens -- --apply
 *   4. Start PR 1 workers (`tmp/restart.txt` / hosting panel)
 *
 * SAFETY GUARANTEES:
 * - Dry-run by default (ZERO database writes unless `--apply` is passed).
 * - Uses an atomic `_auth_maintenance` completion marker so accidental re-runs after
 *   PR 1 start are skipped cleanly without wiping newly issued SHA-256 sessions.
 * - Re-running with `--force` is refused unless paired with `--before=<ISO-8601>` cutoff
 *   earlier than PR 1 startup, keeping post-cutoff rotated sessions untouched.
 * - Never prints token values, emails, phone numbers, or secrets.
 * - Never auto-connects or auto-builds indexes on import (`autoIndex: false`).
 */

import dotenv from "dotenv";
import path from "path";
import mongoose from "mongoose";
import { User } from "../models/mongoose";
import { requireOperationalMongoUrl } from "../utils/resolveMongoUri";

export const AUTH_MAINTENANCE_COLLECTION = "_auth_maintenance";
export const LEGACY_REFRESH_CLEANUP_KEY = "pr1_legacy_refresh_token_cleanup_v1";

export const BASE_LEGACY_SESSION_FILTER: Record<string, unknown> = {
  $or: [
    { refreshToken: { $nin: [null, ""] } },
    { previousRefreshToken: { $nin: [null, ""] } },
    { "previousRefreshTokens.0": { $exists: true } },
    { refreshTokenFamily: { $nin: [null, ""] } },
    { lastRotatedAt: { $ne: null } },
  ],
};

export interface LegacyRefreshCleanupOptions {
  apply?: boolean;
  before?: Date;
  force?: boolean;
  now?: Date;
}

export interface LegacyRefreshCleanupReport {
  mode: "dry_run" | "apply";
  status: "pending" | "completed" | "already_completed";
  applied: boolean;
  skipped: boolean;
  markerKey: string;
  beforeCutoff: string | null;
  startedAt: string;
  completedAt: string | null;
  matchedUsers: number;
  matchedByRole: Record<string, number>;
  modifiedUsers: number;
  remainingWithSessionState: number;
}

interface MaintenanceMarkerDoc {
  _id?: mongoose.Types.ObjectId;
  key: string;
  status: "running" | "completed";
  startedAt?: Date;
  completedAt?: Date;
  beforeCutoff?: Date | null;
  lastMatchedUsers?: number;
  lastModifiedUsers?: number;
  matchedByRole?: Record<string, number>;
}

export const buildLegacySessionFilter = (before?: Date): Record<string, unknown> => {
  if (!before) {
    return BASE_LEGACY_SESSION_FILTER;
  }

  return {
    $and: [
      BASE_LEGACY_SESSION_FILTER,
      {
        $or: [
          { lastRotatedAt: null },
          { lastRotatedAt: { $exists: false } },
          { lastRotatedAt: { $lt: before } },
        ],
      },
    ],
  };
};

const getRoleCounts = async (
  filter: Record<string, unknown>,
): Promise<{ matchedUsers: number; matchedByRole: Record<string, number> }> => {
  const rows = await User.collection
    .aggregate<{ _id: string | null; count: number }>([
      { $match: filter },
      { $group: { _id: "$role", count: { $sum: 1 } } },
      { $sort: { _id: 1 } },
    ])
    .toArray();

  const matchedByRole: Record<string, number> = {};
  let matchedUsers = 0;
  for (const row of rows) {
    const role = typeof row._id === "string" && row._id ? row._id : "UNKNOWN";
    matchedByRole[role] = row.count;
    matchedUsers += row.count;
  }
  return { matchedUsers, matchedByRole };
};

const readExistingMarkerReadOnly = async (
  db: mongoose.mongo.Db,
): Promise<MaintenanceMarkerDoc | null> => {
  const existingCollections = await db
    .listCollections({ name: AUTH_MAINTENANCE_COLLECTION })
    .toArray();
  if (existingCollections.length === 0) {
    return null;
  }

  return db
    .collection<MaintenanceMarkerDoc>(AUTH_MAINTENANCE_COLLECTION)
    .findOne({ key: LEGACY_REFRESH_CLEANUP_KEY });
};

const ensureMaintenanceCollection = async (db: mongoose.mongo.Db) => {
  const existingCollections = await db
    .listCollections({ name: AUTH_MAINTENANCE_COLLECTION })
    .toArray();
  if (existingCollections.length === 0) {
    await db.createCollection(AUTH_MAINTENANCE_COLLECTION);
  }
  const col = db.collection<MaintenanceMarkerDoc>(AUTH_MAINTENANCE_COLLECTION);
  await col.createIndex({ key: 1 }, { unique: true });
  return col;
};

export const runLegacyRefreshTokenCleanup = async (
  options: LegacyRefreshCleanupOptions = {},
): Promise<LegacyRefreshCleanupReport> => {
  const apply = Boolean(options.apply);
  const force = Boolean(options.force);
  const now = options.now ?? new Date();
  const before = options.before;

  if (before !== undefined && Number.isNaN(before.getTime())) {
    throw new Error("Invalid `before` cutoff timestamp.");
  }

  if (force && !before) {
    throw new Error(
      "Refusing `--force` without `--before=<ISO-8601>` cutoff timestamp: forcing a blanket wipe after PR 1 deployment would revoke valid SHA-256 sessions.",
    );
  }

  const db = mongoose.connection.db;
  if (!db) {
    throw new Error("MongoDB connection is not initialized.");
  }

  const filter = buildLegacySessionFilter(before);

  if (!apply) {
    const existingMarker = await readExistingMarkerReadOnly(db);
    const { matchedUsers, matchedByRole } = await getRoleCounts(filter);
    const alreadyDone = existingMarker?.status === "completed";

    return {
      mode: "dry_run",
      status: alreadyDone ? "already_completed" : "pending",
      applied: false,
      skipped: false,
      markerKey: LEGACY_REFRESH_CLEANUP_KEY,
      beforeCutoff: before ? before.toISOString() : null,
      startedAt: now.toISOString(),
      completedAt: existingMarker?.completedAt
        ? new Date(existingMarker.completedAt).toISOString()
        : null,
      matchedUsers,
      matchedByRole,
      modifiedUsers: 0,
      remainingWithSessionState: matchedUsers,
    };
  }

  const col = await ensureMaintenanceCollection(db);
  const existingMarker = await col.findOne({ key: LEGACY_REFRESH_CLEANUP_KEY });

  if (existingMarker?.status === "running") {
    throw new Error(
      "Legacy refresh-token cleanup is already marked as running in another process.",
    );
  }

  if (existingMarker?.status === "completed" && !force) {
    const remainingWithSessionState = await User.collection.countDocuments(filter);
    return {
      mode: "apply",
      status: "already_completed",
      applied: false,
      skipped: true,
      markerKey: LEGACY_REFRESH_CLEANUP_KEY,
      beforeCutoff: before ? before.toISOString() : null,
      startedAt: now.toISOString(),
      completedAt: existingMarker.completedAt
        ? new Date(existingMarker.completedAt).toISOString()
        : null,
      matchedUsers: 0,
      matchedByRole: {},
      modifiedUsers: 0,
      remainingWithSessionState,
    };
  }

  const previousCompletedSnapshot: MaintenanceMarkerDoc | null =
    force && existingMarker ? { ...existingMarker } : null;

  if (!force) {
    try {
      await col.insertOne({
        key: LEGACY_REFRESH_CLEANUP_KEY,
        status: "running",
        startedAt: now,
        beforeCutoff: before ?? null,
      });
    } catch (err: unknown) {
      if ((err as { code?: number })?.code === 11000) {
        const latest = await col.findOne({ key: LEGACY_REFRESH_CLEANUP_KEY });
        if (latest?.status === "completed") {
          const remainingWithSessionState = await User.collection.countDocuments(filter);
          return {
            mode: "apply",
            status: "already_completed",
            applied: false,
            skipped: true,
            markerKey: LEGACY_REFRESH_CLEANUP_KEY,
            beforeCutoff: before ? before.toISOString() : null,
            startedAt: now.toISOString(),
            completedAt: latest.completedAt
              ? new Date(latest.completedAt).toISOString()
              : null,
            matchedUsers: 0,
            matchedByRole: {},
            modifiedUsers: 0,
            remainingWithSessionState,
          };
        }
        throw new Error("Legacy refresh-token cleanup claim conflict (already running).");
      }
      throw err;
    }
  } else {
    const claimed = await col.findOneAndUpdate(
      { key: LEGACY_REFRESH_CLEANUP_KEY, status: { $ne: "running" } },
      {
        $set: {
          key: LEGACY_REFRESH_CLEANUP_KEY,
          status: "running",
          startedAt: now,
          beforeCutoff: before ?? null,
        },
      },
      { upsert: true, returnDocument: "after" },
    );
    if (!claimed || claimed.status !== "running") {
      throw new Error("Could not acquire forced legacy refresh-token cleanup lock.");
    }
  }

  try {
    const { matchedUsers, matchedByRole } = await getRoleCounts(filter);

    const updateResult = await User.collection.updateMany(filter, [
      {
        $set: {
          refreshToken: null,
          previousRefreshToken: null,
          previousRefreshTokens: [],
          refreshTokenFamily: null,
          lastRotatedAt: null,
          tokenVersion: {
            $add: [
              {
                $cond: [{ $isNumber: "$tokenVersion" }, "$tokenVersion", 0],
              },
              1,
            ],
          },
        },
      },
    ]);

    const completedAt = new Date();
    const remainingWithSessionState = await User.collection.countDocuments(filter);

    await col.updateOne(
      { key: LEGACY_REFRESH_CLEANUP_KEY },
      {
        $set: {
          status: "completed",
          completedAt,
          beforeCutoff: before ?? null,
          lastMatchedUsers: matchedUsers,
          lastModifiedUsers: updateResult.modifiedCount,
          matchedByRole,
        },
      },
    );

    return {
      mode: "apply",
      status: "completed",
      applied: true,
      skipped: false,
      markerKey: LEGACY_REFRESH_CLEANUP_KEY,
      beforeCutoff: before ? before.toISOString() : null,
      startedAt: now.toISOString(),
      completedAt: completedAt.toISOString(),
      matchedUsers,
      matchedByRole,
      modifiedUsers: updateResult.modifiedCount,
      remainingWithSessionState,
    };
  } catch (err) {
    if (previousCompletedSnapshot?._id) {
      await col.replaceOne(
        { _id: previousCompletedSnapshot._id },
        previousCompletedSnapshot,
      );
    } else {
      await col.deleteOne({
        key: LEGACY_REFRESH_CLEANUP_KEY,
        status: "running",
      });
    }
    throw err;
  }
};

export interface ParsedCleanupCliArgs {
  apply: boolean;
  force: boolean;
  json: boolean;
  before?: Date;
}

export const parseCleanupCliArgs = (argv: string[]): ParsedCleanupCliArgs => {
  let apply = false;
  let force = false;
  let json = false;
  let before: Date | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--apply") {
      apply = true;
    } else if (arg === "--force") {
      force = true;
    } else if (arg === "--json") {
      json = true;
    } else if (arg === "--before") {
      const next = argv[i + 1];
      if (!next) {
        throw new Error("Missing value after `--before`. Expected an ISO-8601 timestamp.");
      }
      const parsed = new Date(next);
      if (Number.isNaN(parsed.getTime())) {
        throw new Error(`Invalid \`--before\` timestamp: "${next}".`);
      }
      before = parsed;
      i++;
    } else if (arg.startsWith("--before=")) {
      const raw = arg.slice("--before=".length);
      const parsed = new Date(raw);
      if (!raw || Number.isNaN(parsed.getTime())) {
        throw new Error(`Invalid \`--before\` timestamp: "${raw}".`);
      }
      before = parsed;
    } else {
      throw new Error(
        `Unknown argument "${arg}". Supported flags: [--apply] [--before=<ISO-8601>] [--force] [--json]`,
      );
    }
  }

  return { apply, force, json, before };
};

export const formatLegacyRefreshCleanupSummary = (
  report: LegacyRefreshCleanupReport,
): string => {
  const roleEntries = Object.entries(report.matchedByRole);
  const roleSummary =
    roleEntries.length > 0
      ? roleEntries.map(([role, count]) => `${role}=${count}`).join(", ")
      : "none";

  const lines = [
    "=== PR 1 Controlled Legacy Refresh-Token Cleanup ===",
    `Mode                       : ${report.mode.toUpperCase()}`,
    `Status                     : ${report.status.toUpperCase()}`,
    `Marker Key                 : ${report.markerKey}`,
    `Cutoff (--before)          : ${report.beforeCutoff ?? "none (full pre-PR-1 sweep)"}`,
    `Matched Users              : ${report.matchedUsers} (${roleSummary})`,
    `Modified Users             : ${report.modifiedUsers}`,
    `Remaining Matching Users   : ${report.remainingWithSessionState}`,
  ];

  if (report.completedAt) {
    lines.push(`Completed At               : ${report.completedAt}`);
  }

  if (report.mode === "dry_run" && report.status === "pending") {
    lines.push(
      "",
      "NEXT CONTROLLED CUTOVER STEPS:",
      "  1. Stop all pre-PR-1 app workers / enable maintenance mode.",
      "  2. Run: npm run auth:cleanup-legacy-tokens -- --apply",
      "  3. Start PR 1 app workers so only tokenVersion + SHA-256 refresh sessions are minted.",
    );
  } else if (report.status === "already_completed" && report.skipped) {
    lines.push(
      "",
      "SKIPPED: One-time cleanup already completed; existing post-PR-1 SHA-256 sessions were left untouched.",
    );
  }

  return lines.join("\n");
};

const runCli = async () => {
  dotenv.config({ path: path.resolve(process.cwd(), ".env") });
  dotenv.config({ path: path.resolve(__dirname, "../../.env") });

  let parsedArgs: ParsedCleanupCliArgs;
  try {
    parsedArgs = parseCleanupCliArgs(process.argv.slice(2));
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(2);
    return;
  }

  let mongoUrl: string;
  try {
    mongoUrl = requireOperationalMongoUrl("legacy refresh-token cleanup");
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

    const report = await runLegacyRefreshTokenCleanup({
      apply: parsedArgs.apply,
      force: parsedArgs.force,
      before: parsedArgs.before,
    });

    if (parsedArgs.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(formatLegacyRefreshCleanupSummary(report));
    }

    await mongoose.disconnect();
    process.exit(0);
  } catch (err) {
    console.error("Legacy refresh-token cleanup failed:", err);
    try {
      await mongoose.disconnect();
    } catch {}
    process.exit(1);
  }
};

if (require.main === module) {
  void runCli();
}

