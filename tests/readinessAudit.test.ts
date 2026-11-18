import mongoose from "mongoose";
import {
  Address,
  Order,
  OrderArchive,
  PaymentLog,
  User,
} from "../src/models/mongoose";
import {
  formatReadinessSummary,
  generateCustomerEmailReadinessReport,
} from "../src/scripts/auditCustomerEmailReadiness";
import { clearTestDb, startTestDb, stopTestDb } from "./helpers/testDb";

describe("PR 1 — Strictly read-only customer email readiness audit (#17)", () => {
  beforeAll(async () => {
    await startTestDb();
  });

  afterEach(async () => {
    await clearTestDb();
  });

  afterAll(async () => {
    await stopTestDb();
  });

  it("reports duplicates across roles, null/empty/malformed/non-normalized emails, POS candidates, invalid phones, and reference counts with ZERO database writes", async () => {
    // Wait for Mongoose's initial autoIndex builds BEFORE seeding/snapshotting so
    // background schema index creation cannot race with the read-only index check.
    await Promise.all([
      User.init(),
      Order.init(),
      OrderArchive.init(),
      PaymentLog.init(),
      Address.init(),
    ]);

    // 1. Seed mixed production-like anomalies across all roles directly into collection
    const adminId = new mongoose.Types.ObjectId();
    const custDupEmailId = new mongoose.Types.ObjectId();
    const custNullEmailId = new mongoose.Types.ObjectId();
    const custEmptyEmailId = new mongoose.Types.ObjectId();
    const custMalformedEmailId = new mongoose.Types.ObjectId();
    const custNonNormalizedId = new mongoose.Types.ObjectId();
    const custPosCandidateId = new mongoose.Types.ObjectId();
    const custHistoricalPwId = new mongoose.Types.ObjectId();
    const staffDupPhoneId = new mongoose.Types.ObjectId();

    await User.collection.insertMany([
      {
        _id: adminId,
        username: "Store Admin",
        email: "shared@storra.test",
        phone: "9811111111",
        password: "hashed_pw",
        role: "ADMIN",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      },
      {
        _id: custDupEmailId,
        username: "Dup Email Customer",
        email: "  Shared@Storra.TEST ",
        phone: "9822222222",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: null,
        tokenVersion: 0,
      },
      {
        _id: custNullEmailId,
        username: "Null Email POS Customer",
        email: null,
        phone: "+919833333333", // non-canonical phone format
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: null,
        tokenVersion: 0,
      },
      {
        _id: custEmptyEmailId,
        username: "Empty Email Customer",
        email: "   ",
        phone: "12345", // invalid phone
        role: "CUSTOMER",
        isActive: true,
        isVerified: false,
        emailVerifiedAt: null,
        tokenVersion: 0,
      },
      {
        _id: custMalformedEmailId,
        username: "Malformed Email Customer",
        email: "not-an-email",
        phone: "9844444444",
        role: "CUSTOMER",
        isActive: true,
        isVerified: false,
        emailVerifiedAt: null,
        tokenVersion: 0,
      },
      {
        _id: custNonNormalizedId,
        username: "Case Email Customer",
        email: "UpperCase@Storra.test",
        phone: "9855555555",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: new Date("2025-01-01T00:00:00.000Z"),
        tokenVersion: 0,
      },
      {
        _id: custPosCandidateId,
        username: "POS Clean Customer",
        email: "pos.clean@storra.test",
        phone: "9866666666",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: null,
        tokenVersion: 0,
      },
      {
        _id: custHistoricalPwId,
        username: "Verified Clean Customer With Legacy Pw",
        email: "verified.clean@storra.test",
        phone: "9877777777",
        password: "$2a$10$legacybcryptpasswordhash",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: new Date("2025-02-01T00:00:00.000Z"),
        tokenVersion: 0,
      },
      {
        _id: staffDupPhoneId,
        username: "Staff Duplicate Phone",
        email: "staff.dup@storra.test",
        phone: "919822222222", // normalizes to same 9822222222 as custDupEmailId
        role: "STAFF",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      },
    ]);

    // 2. Seed orders, archived orders, payment logs, and addresses for affected accounts
    const orderId1 = new mongoose.Types.ObjectId();
    const orderId2 = new mongoose.Types.ObjectId();
    await Order.collection.insertMany([
      {
        _id: orderId1,
        userId: custDupEmailId,
        totalAmount: 500,
        finalAmount: 500,
        paymentMethod: "ONLINE",
        paymentStatus: "PAID",
        orderStatus: "DELIVERED",
        shippingAddress: { city: "Kochi" },
      },
      {
        _id: orderId2,
        userId: adminId,
        totalAmount: 100,
        finalAmount: 100,
        paymentMethod: "CASH",
        paymentStatus: "PAID",
        orderStatus: "DELIVERED",
        shippingAddress: { city: "TVM" },
      },
    ]);

    await OrderArchive.collection.insertOne({
      originalId: new mongoose.Types.ObjectId(),
      userId: custDupEmailId,
      orderData: { finalAmount: 250 },
      items: [],
    });

    await PaymentLog.collection.insertOne({
      userId: custDupEmailId,
      orderId: orderId1,
      amount: 500,
      paymentStatus: "PAID",
      paymentMethod: "ONLINE",
    });

    await Address.collection.insertMany([
      {
        userId: custDupEmailId,
        fullAddress: "123 MG Road",
        city: "Kochi",
        state: "Kerala",
        zipCode: "682001",
      },
      {
        userId: custNullEmailId,
        fullAddress: "456 Park Ave",
        city: "Kochi",
        state: "Kerala",
        zipCode: "682002",
      },
    ]);

    // Snapshot DB bytes before audit to assert zero mutations occurred
    const beforeUsersSnapshot = JSON.stringify(
      await User.collection.find({}).sort({ _id: 1 }).toArray(),
    );
    const beforeOrdersSnapshot = JSON.stringify(
      await Order.collection.find({}).sort({ _id: 1 }).toArray(),
    );
    const beforeIndexesSnapshot = JSON.stringify(await User.collection.indexes());

    const report = await generateCustomerEmailReadinessReport();

    // Verify zero writes, zero merges, and zero index creations
    const afterUsersSnapshot = JSON.stringify(
      await User.collection.find({}).sort({ _id: 1 }).toArray(),
    );
    const afterOrdersSnapshot = JSON.stringify(
      await Order.collection.find({}).sort({ _id: 1 }).toArray(),
    );
    const afterIndexesSnapshot = JSON.stringify(await User.collection.indexes());

    expect(afterUsersSnapshot).toBe(beforeUsersSnapshot);
    expect(afterOrdersSnapshot).toBe(beforeOrdersSnapshot);
    expect(afterIndexesSnapshot).toBe(beforeIndexesSnapshot);
    expect(report.readOnlyVerified).toBe(true);

    // Verify exact counts & cross-role conflict metrics
    expect(report.totals.totalUsers).toBe(9);
    expect(report.blockerCounts.missingOrEmptyCustomerEmails).toBe(2); // null + "   "
    expect(report.blockerCounts.malformedCustomerEmails).toBe(1); // "not-an-email"
    expect(report.blockerCounts.nonNormalizedCustomerEmails).toBe(2); // "  Shared@Storra.TEST " + "UpperCase@Storra.test"
    expect(report.blockerCounts.duplicateNormalizedEmails).toBe(1); // shared@storra.test
    expect(report.blockerCounts.duplicatePhones).toBe(1); // 9822222222 vs 919822222222
    expect(report.blockerCounts.invalidPhones).toBe(3); // +919833333333, 12345, 919822222222

    expect(report.readinessCounts.unverifiedCustomerEmails).toBe(5);
    expect(report.readinessCounts.posActivationCandidates).toBe(3); // custDupEmail, custNullEmail, custPosCandidate
    expect(report.readinessCounts.historicalCustomerPasswords).toBe(1);
    expect(report.hasBlockers).toBe(true);
    expect(report.isCutoverReady).toBe(false);

    // Verify order/archive/payment/address counts per duplicate email user
    const dupGroup = report.crossRoleConflicts.duplicateNormalizedEmails[0];
    expect(dupGroup.key).toBe("shared@storra.test");
    expect(dupGroup.roles.sort()).toEqual(["ADMIN", "CUSTOMER"]);

    const dupCustomerRef = dupGroup.users.find((u) => u.id === String(custDupEmailId))!;
    expect(dupCustomerRef.references).toEqual({
      ordersCount: 1,
      archivedOrdersCount: 1,
      paymentLogsCount: 1,
      addressesCount: 1,
    });

    const summary = formatReadinessSummary(report);
    expect(summary).toContain("shared@storra.test");
    expect(summary).toContain("Has Schema/Index Blockers          : YES");
  });

  it("reports zero blockers and cutover readiness when all users are clean and verified", async () => {
    await User.collection.insertMany([
      {
        username: "Clean Customer",
        email: "clean.customer@storra.test",
        phone: "9899999999",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: new Date(),
        tokenVersion: 0,
      },
      {
        username: "Clean Admin",
        email: "clean.admin@storra.test",
        phone: "9800000001",
        password: "hash",
        role: "ADMIN",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      },
    ]);

    const report = await generateCustomerEmailReadinessReport();
    expect(report.hasBlockers).toBe(false);
    expect(report.isCutoverReady).toBe(true);
  });
});

