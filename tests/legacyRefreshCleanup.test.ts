import crypto from "crypto";
import mongoose from "mongoose";
import { User } from "../src/models/mongoose";
import { hashRefreshTokenValue } from "../src/config/tokens";
import {
  AUTH_MAINTENANCE_COLLECTION,
  LEGACY_REFRESH_CLEANUP_KEY,
  formatLegacyRefreshCleanupSummary,
  parseCleanupCliArgs,
  runLegacyRefreshTokenCleanup,
} from "../src/scripts/cleanupLegacyRefreshTokens";
import { clearTestDb, startTestDb, stopTestDb } from "./helpers/testDb";

describe("PR 1 — Controlled one-time legacy refresh-token cleanup script", () => {
  beforeAll(async () => {
    await startTestDb();
    await User.init();
  });

  afterEach(async () => {
    const db = mongoose.connection.db;
    if (db) {
      const collections = await db
        .listCollections({ name: AUTH_MAINTENANCE_COLLECTION })
        .toArray();
      if (collections.length > 0) {
        await db.collection(AUTH_MAINTENANCE_COLLECTION).deleteMany({});
      }
    }
    await clearTestDb();
  });

  afterAll(async () => {
    await stopTestDb();
  });

  it("defaults to strictly read-only dry-run and detects both 64-hex legacy tokens and rotation arrays without touching users or creating marker collections", async () => {
    const legacyHex = crypto.randomBytes(32).toString("hex");
    await User.collection.insertMany([
      {
        username: "Legacy Customer",
        email: "legacy.cust@storra.test",
        phone: "9811100001",
        role: "CUSTOMER",
        refreshToken: legacyHex,
        previousRefreshToken: crypto.randomBytes(32).toString("hex"),
        previousRefreshTokens: [
          { token: crypto.randomBytes(32).toString("hex"), rotatedAt: new Date("2026-01-01T00:00:00Z") },
        ],
        refreshTokenFamily: "legacy-family-1",
        lastRotatedAt: new Date("2026-01-02T00:00:00Z"),
        isActive: true,
        isVerified: true,
      },
      {
        username: "Clean Customer No Session",
        email: "clean.nosess@storra.test",
        phone: "9811100002",
        role: "CUSTOMER",
        refreshToken: null,
        refreshTokenFamily: null,
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      },
    ]);

    const beforeSnapshot = JSON.stringify(
      await User.collection.find({}).sort({ _id: 1 }).toArray(),
    );

    const report = await runLegacyRefreshTokenCleanup();
    expect(report.mode).toBe("dry_run");
    expect(report.status).toBe("pending");
    expect(report.applied).toBe(false);
    expect(report.matchedUsers).toBe(1);
    expect(report.matchedByRole).toEqual({ CUSTOMER: 1 });
    expect(report.modifiedUsers).toBe(0);

    const afterSnapshot = JSON.stringify(
      await User.collection.find({}).sort({ _id: 1 }).toArray(),
    );
    expect(afterSnapshot).toBe(beforeSnapshot);

    const markerCols = await mongoose.connection.db!
      .listCollections({ name: AUTH_MAINTENANCE_COLLECTION })
      .toArray();
    expect(markerCols).toHaveLength(0);

    const summary = formatLegacyRefreshCleanupSummary(report);
    expect(summary).toContain("DRY_RUN");
    expect(summary).toContain("Matched Users              : 1 (CUSTOMER=1)");
  });

  it("clears all legacy refresh state, increments tokenVersion (even when missing or null), preserves clean accounts, and prevents accidental second runs after PR 1 sessions exist", async () => {
    const legacyCustomerId = new mongoose.Types.ObjectId();
    const legacyAdminId = new mongoose.Types.ObjectId();
    const idleCustomerId = new mongoose.Types.ObjectId();

    await User.collection.insertMany([
      {
        _id: legacyCustomerId,
        username: "Legacy Cust Missing TokenVersion",
        email: "cust.legacy@storra.test",
        phone: "9822200001",
        role: "CUSTOMER",
        refreshToken: crypto.randomBytes(32).toString("hex"),
        previousRefreshToken: crypto.randomBytes(32).toString("hex"),
        previousRefreshTokens: [
          { token: crypto.randomBytes(32).toString("hex"), rotatedAt: new Date("2026-01-01T00:00:00Z") },
        ],
        refreshTokenFamily: "fam-cust-1",
        lastRotatedAt: new Date("2026-01-01T01:00:00Z"),
        isActive: true,
        isVerified: true,
        // Intentionally omit tokenVersion to test legacy pre-PR-1 doc handling
      },
      {
        _id: legacyAdminId,
        username: "Legacy Admin Null TokenVersion",
        email: "admin.legacy@storra.test",
        phone: "9822200002",
        role: "ADMIN",
        tokenVersion: null,
        refreshToken: crypto.randomBytes(32).toString("hex"),
        refreshTokenFamily: "fam-admin-1",
        lastRotatedAt: new Date("2026-01-02T00:00:00Z"),
        isActive: true,
        isVerified: true,
      },
      {
        _id: idleCustomerId,
        username: "Idle Customer",
        email: "idle@storra.test",
        phone: "9822200003",
        role: "CUSTOMER",
        tokenVersion: 4,
        refreshToken: null,
        previousRefreshToken: null,
        previousRefreshTokens: [],
        refreshTokenFamily: null,
        lastRotatedAt: null,
        isActive: true,
        isVerified: true,
      },
    ]);

    // 1. Pre-PR-1 controlled one-time execution
    const firstRun = await runLegacyRefreshTokenCleanup({ apply: true });
    expect(firstRun.mode).toBe("apply");
    expect(firstRun.status).toBe("completed");
    expect(firstRun.applied).toBe(true);
    expect(firstRun.skipped).toBe(false);
    expect(firstRun.matchedUsers).toBe(2);
    expect(firstRun.matchedByRole).toEqual({ ADMIN: 1, CUSTOMER: 1 });
    expect(firstRun.modifiedUsers).toBe(2);
    expect(firstRun.remainingWithSessionState).toBe(0);

    const cleanedCust = await User.collection.findOne({ _id: legacyCustomerId });
    expect(cleanedCust?.refreshToken).toBeNull();
    expect(cleanedCust?.previousRefreshToken).toBeNull();
    expect(cleanedCust?.previousRefreshTokens).toEqual([]);
    expect(cleanedCust?.refreshTokenFamily).toBeNull();
    expect(cleanedCust?.lastRotatedAt).toBeNull();
    expect(cleanedCust?.tokenVersion).toBe(1);
    expect(cleanedCust?.email).toBe("cust.legacy@storra.test");

    const cleanedAdmin = await User.collection.findOne({ _id: legacyAdminId });
    expect(cleanedAdmin?.refreshToken).toBeNull();
    expect(cleanedAdmin?.tokenVersion).toBe(1);

    const untouchedIdle = await User.collection.findOne({ _id: idleCustomerId });
    expect(untouchedIdle?.tokenVersion).toBe(4);

    // 2. Simulate PR 1 starting and issuing a real 64-hex SHA-256 refresh digest!
    const pr1Sha256Digest = hashRefreshTokenValue(crypto.randomBytes(32).toString("hex"));
    await User.collection.updateOne(
      { _id: legacyCustomerId },
      {
        $set: {
          refreshToken: pr1Sha256Digest,
          refreshTokenFamily: "fam-pr1-new",
          lastRotatedAt: new Date("2026-02-01T12:00:00Z"),
        },
      },
    );

    // 3. Re-running `--apply` after PR 1 start MUST skip cleanly and preserve the PR 1 SHA-256 session
    const secondRun = await runLegacyRefreshTokenCleanup({ apply: true });
    expect(secondRun.status).toBe("already_completed");
    expect(secondRun.applied).toBe(false);
    expect(secondRun.skipped).toBe(true);
    expect(secondRun.modifiedUsers).toBe(0);

    const postPr1Cust = await User.collection.findOne({ _id: legacyCustomerId });
    expect(postPr1Cust?.refreshToken).toBe(pr1Sha256Digest);
    expect(postPr1Cust?.refreshTokenFamily).toBe("fam-pr1-new");
    expect(postPr1Cust?.tokenVersion).toBe(1);

    const markerDoc = await mongoose.connection.db!
      .collection(AUTH_MAINTENANCE_COLLECTION)
      .findOne({ key: LEGACY_REFRESH_CLEANUP_KEY });
    expect(markerDoc?.status).toBe("completed");
  });

  it("requires --before cutoff when --force is used and preserves sessions rotated at or after --before", async () => {
    const cutoverAt = new Date("2026-02-01T10:00:00.000Z");
    const preCutoverId = new mongoose.Types.ObjectId();
    const postCutoverId = new mongoose.Types.ObjectId();
    const pr1Sha256 = hashRefreshTokenValue(crypto.randomBytes(32).toString("hex"));

    await User.collection.insertMany([
      {
        _id: preCutoverId,
        username: "Missed Pre-Cutover Session",
        email: "pre@storra.test",
        phone: "9833300001",
        role: "CUSTOMER",
        tokenVersion: 0,
        refreshToken: crypto.randomBytes(32).toString("hex"),
        refreshTokenFamily: "old-fam",
        lastRotatedAt: new Date("2026-02-01T09:59:59.000Z"),
      },
      {
        _id: postCutoverId,
        username: "New PR 1 Session",
        email: "post@storra.test",
        phone: "9833300002",
        role: "CUSTOMER",
        tokenVersion: 0,
        refreshToken: pr1Sha256,
        refreshTokenFamily: "new-pr1-fam",
        lastRotatedAt: new Date("2026-02-01T10:00:05.000Z"),
      },
    ]);

    // Refuses `--force` without `--before`
    await expect(
      runLegacyRefreshTokenCleanup({ apply: true, force: true }),
    ).rejects.toThrow(/--before=/);

    // Forced cleanup with explicit `--before` cleans pre-cutover ONLY while leaving PR 1 SHA-256 intact
    const forced = await runLegacyRefreshTokenCleanup({
      apply: true,
      force: true,
      before: cutoverAt,
    });
    expect(forced.status).toBe("completed");
    expect(forced.modifiedUsers).toBe(1);
    expect(forced.remainingWithSessionState).toBe(0);

    const preDoc = await User.collection.findOne({ _id: preCutoverId });
    expect(preDoc?.refreshToken).toBeNull();
    expect(preDoc?.tokenVersion).toBe(1);

    const postDoc = await User.collection.findOne({ _id: postCutoverId });
    expect(postDoc?.refreshToken).toBe(pr1Sha256);
    expect(postDoc?.refreshTokenFamily).toBe("new-pr1-fam");
    expect(postDoc?.tokenVersion).toBe(0);
  });

  it("parses CLI flags strictly and rejects unknown or invalid arguments", () => {
    expect(parseCleanupCliArgs([])).toEqual({
      apply: false,
      force: false,
      json: false,
      before: undefined,
    });

    const parsed = parseCleanupCliArgs([
      "--apply",
      "--force",
      "--json",
      "--before=2026-02-01T10:00:00.000Z",
    ]);
    expect(parsed.apply).toBe(true);
    expect(parsed.force).toBe(true);
    expect(parsed.json).toBe(true);
    expect(parsed.before?.toISOString()).toBe("2026-02-01T10:00:00.000Z");

    expect(() => parseCleanupCliArgs(["--before=not-a-date"])).toThrow();
    expect(() => parseCleanupCliArgs(["--unknown-flag"])).toThrow();
  });
});

