import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import request from "supertest";
import { createApp } from "../src/server";
import { env } from "../src/config/env";
import { registerCustomer } from "../src/controllers/auth.controller";
import {
  AuditLog,
  AppSetting,
  Category,
  Coupon,
  Notification,
  Order,
  OrderItem,
  PaymentLog,
  Product,
  ProductVariant,
  User,
} from "../src/models/mongoose";
import {
  ensurePrepEmailUniqueIndex,
  formatPrepEmailIndexSummary,
  PREP_EMAIL_UNIQUE_INDEX_NAME,
} from "../src/scripts/ensurePrepEmailUniqueIndex";
import {
  bootstrapCsrfAgent,
  nextTestIp,
} from "./helpers/httpHelper";
import { clearTestDb, startTestDb, stopTestDb } from "./helpers/testDb";

const dropPrepEmailIndexIfExists = async () => {
  if (mongoose.connection.readyState !== 1) return;
  const indexes = await User.collection.indexes();
  if (indexes.some((i) => i.name === PREP_EMAIL_UNIQUE_INDEX_NAME)) {
    await User.collection.dropIndex(PREP_EMAIL_UNIQUE_INDEX_NAME);
  }
};

const mockMsg91PhoneLookup = () =>
  jest.spyOn(globalThis, "fetch").mockImplementation(async (url, init) => {
    const urlStr = String(url);
    if (urlStr.includes("/widget/verifyAccessToken")) {
      const payload = JSON.parse(String(init?.body ?? "{}")) as Record<string, string>;
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            type: "success",
            data: { mobile: payload["access-token"] },
          }),
      } as globalThis.Response;
    }
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ status: "success" }),
    } as globalThis.Response;
  });

const createMockRes = () => {
  const res: Record<string, unknown> = {
    statusCode: 200,
    body: null,
  };
  res.status = jest.fn((code: number) => {
    res.statusCode = code;
    return res;
  });
  res.json = jest.fn((payload: unknown) => {
    res.body = payload;
    return res;
  });
  return res as unknown as {
    statusCode: number;
    body: unknown;
    status: jest.Mock;
    json: jest.Mock;
  };
};

describe("PR 1 Final Correction — Mandatory Customer Email & Phone + Prep Index", () => {
  let appCtx: ReturnType<typeof createApp>;

  beforeAll(async () => {
    await startTestDb();
    await Promise.all([
      User.init(),
      Category.init(),
      Product.init(),
      ProductVariant.init(),
      Order.init(),
      OrderItem.init(),
      PaymentLog.init(),
      Coupon.init(),
      Notification.init(),
      AuditLog.init(),
      AppSetting.init(),
    ]);
    appCtx = createApp();
  });

  afterEach(async () => {
    jest.restoreAllMocks();
    await dropPrepEmailIndexIfExists();
    await clearTestDb();
  });

  afterAll(async () => {
    await dropPrepEmailIndexIfExists();
    if (appCtx) {
      appCtx.stopSocketRecheck();
      await new Promise<void>((resolve) => appCtx.io.close(() => resolve()));
    }
    await stopTestDb();
  });

  describe("1. Customer SMS signup mandatory email & phone validation", () => {
    it("rejects missing, null, empty, and malformed email values on POST /api/auth/mobile/register without calling MSG91", async () => {
      const fetchSpy = mockMsg91PhoneLookup();
      const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

      const invalidEmailPayloads: Array<Record<string, unknown>> = [
        { name: "Alice Shopper", phone: "9876543210", accessToken: "919876543210" },
        { name: "Alice Shopper", email: null, phone: "9876543210", accessToken: "919876543210" },
        { name: "Alice Shopper", email: "", phone: "9876543210", accessToken: "919876543210" },
        { name: "Alice Shopper", email: "   ", phone: "9876543210", accessToken: "919876543210" },
        { name: "Alice Shopper", email: "invalid-email", phone: "9876543210", accessToken: "919876543210" },
        { name: "Alice Shopper", email: "user@localhost", phone: "9876543210", accessToken: "919876543210" },
        { name: "Alice Shopper", email: "bad..dots@storra.test", phone: "9876543210", accessToken: "919876543210" },
      ];

      for (const payload of invalidEmailPayloads) {
        const res = await agent
          .post("/api/auth/mobile/register")
          .set("Origin", origin)
          .set("X-CSRF-Token", csrfToken)
          .set("X-Forwarded-For", nextTestIp())
          .send(payload);
        expect(res.status).toBe(400);
      }

      expect(fetchSpy).not.toHaveBeenCalled();
      expect(await User.countDocuments()).toBe(0);
    });

    it("rejects missing, null, empty, and non-Indian phone values on POST /api/auth/mobile/register without calling MSG91", async () => {
      const fetchSpy = mockMsg91PhoneLookup();
      const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

      const invalidPhonePayloads: Array<Record<string, unknown>> = [
        { name: "Alice Shopper", email: "alice@storra.test", accessToken: "919876543210" },
        { name: "Alice Shopper", email: "alice@storra.test", phone: null, accessToken: "919876543210" },
        { name: "Alice Shopper", email: "alice@storra.test", phone: "", accessToken: "919876543210" },
        { name: "Alice Shopper", email: "alice@storra.test", phone: "   ", accessToken: "919876543210" },
        { name: "Alice Shopper", email: "alice@storra.test", phone: "12345", accessToken: "919876543210" },
        { name: "Alice Shopper", email: "alice@storra.test", phone: "5876543210", accessToken: "919876543210" },
        { name: "Alice Shopper", email: "alice@storra.test", phone: "+919876543210", accessToken: "919876543210" },
      ];

      for (const payload of invalidPhonePayloads) {
        const res = await agent
          .post("/api/auth/mobile/register")
          .set("Origin", origin)
          .set("X-CSRF-Token", csrfToken)
          .set("X-Forwarded-For", nextTestIp())
          .send(payload);
        expect(res.status).toBe(400);
      }

      expect(fetchSpy).not.toHaveBeenCalled();
      expect(await User.countDocuments()).toBe(0);
    });

    it("enforces defense-in-depth validation directly inside registerCustomer controller if middleware is bypassed", async () => {
      const fetchSpy = mockMsg91PhoneLookup();
      const cases = [
        { name: "Bob", email: undefined, phone: "9876543210", accessToken: "919876543210" },
        { name: "Bob", email: null, phone: "9876543210", accessToken: "919876543210" },
        { name: "Bob", email: "", phone: "9876543210", accessToken: "919876543210" },
        { name: "Bob", email: "not-valid", phone: "9876543210", accessToken: "919876543210" },
        { name: "Bob", email: "bob@storra.test", phone: "", accessToken: "919876543210" },
        { name: "Bob", email: "bob@storra.test", phone: null, accessToken: "919876543210" },
        { name: "Bob", email: "bob@storra.test", phone: "4999999999", accessToken: "919876543210" },
      ];

      for (const body of cases) {
        const res = createMockRes();
        await registerCustomer({ body, ip: "127.0.0.1" } as never, res as never);
        expect(res.statusCode).toBe(400);
      }

      expect(fetchSpy).not.toHaveBeenCalled();
      expect(await User.countDocuments()).toBe(0);
    });

    it("creates customer with trimmed lowercase email, canonical phone, emailVerifiedAt: null, and allows SMS login", async () => {
      mockMsg91PhoneLookup();
      const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

      const regRes = await agent
        .post("/api/auth/mobile/register")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({
          name: "  Priya Nair ",
          email: "  Priya.Nair+Shop@Storra.TEST ",
          phone: "9876501234",
          accessToken: "919876501234",
        });

      expect(regRes.status).toBe(201);
      expect(regRes.body.user?.username).toBe("Priya Nair");
      expect(regRes.body.user?.role).toBe("CUSTOMER");

      const created = await User.findOne({ phone: "9876501234" }).lean();
      expect(created).toBeTruthy();
      expect(created?.email).toBe("priya.nair+shop@storra.test");
      expect(created?.phone).toBe("9876501234");
      expect(created?.isVerified).toBe(true);
      expect(created?.emailVerifiedAt).toBeNull();

      // Existing SMS login flow still succeeds for this newly created customer
      const loginRes = await agent
        .post("/api/auth/mobile/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({
          phone: "9876501234",
          accessToken: "919876501234",
        });
      expect(loginRes.status).toBe(200);
      expect(loginRes.body.user?.id).toBe(String(created!._id));
    });

    it("returns identical non-enumerating 409 DUPLICATE responses for duplicate email and duplicate phone across roles", async () => {
      mockMsg91PhoneLookup();
      await User.insertMany([
        {
          username: "Existing Customer",
          email: "existing.cust@storra.test",
          phone: "9811112222",
          role: "CUSTOMER",
          isVerified: true,
          isActive: true,
          emailVerifiedAt: null,
        },
        {
          username: "Store Admin",
          email: "owner@storra.test",
          phone: "9833334444",
          role: "ADMIN",
          isVerified: true,
          isActive: true,
        },
      ]);

      const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

      // Duplicate CUSTOMER email (different phone, mixed case input)
      const dupCustEmail = await agent
        .post("/api/auth/mobile/register")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({
          name: "Clone User",
          email: "  EXISTING.CUST@Storra.TEST ",
          phone: "9899990001",
          accessToken: "919899990001",
        });

      // Duplicate ADMIN email (different phone)
      const dupAdminEmail = await agent
        .post("/api/auth/mobile/register")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({
          name: "Clone User",
          email: "owner@storra.test",
          phone: "9899990002",
          accessToken: "919899990002",
        });

      // Duplicate phone (new email)
      const dupPhone = await agent
        .post("/api/auth/mobile/register")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({
          name: "Clone User",
          email: "brand.new@storra.test",
          phone: "9811112222",
          accessToken: "919811112222",
        });

      for (const r of [dupCustEmail, dupAdminEmail, dupPhone]) {
        expect(r.status).toBe(409);
        expect(r.body.code).toBe("DUPLICATE");
        expect(r.body.conflictField).toBeUndefined();
        expect(JSON.stringify(r.body)).not.toMatch(/ADMIN|CUSTOMER|phone|email/i);
      }
      expect(dupCustEmail.body).toEqual(dupAdminEmail.body);
      expect(dupAdminEmail.body).toEqual(dupPhone.body);
    });
  });

  describe("2. Transitional preparation-window email partial unique index & concurrent race protection", () => {
    it("refuses --apply when duplicate normalized or non-normalized emails exist", async () => {
      await User.collection.insertMany([
        {
          username: "Admin User",
          email: "DupUser@Storra.test",
          phone: "9800010001",
          role: "ADMIN",
          isVerified: true,
          isActive: true,
        },
        {
          username: "Customer User",
          email: "dupuser@storra.test",
          phone: "9800010002",
          role: "CUSTOMER",
          isVerified: true,
          isActive: true,
          emailVerifiedAt: null,
        },
        {
          username: "Whitespace User",
          email: "   ",
          phone: "9800010003",
          role: "CUSTOMER",
          isVerified: true,
          isActive: true,
          emailVerifiedAt: null,
        },
      ]);

      const blockedResult = await ensurePrepEmailUniqueIndex({ apply: true });
      expect(blockedResult.status).toBe("blocked");
      expect(blockedResult.applied).toBe(false);
      expect(blockedResult.audit.duplicateNormalizedEmails).toBe(1);
      expect(blockedResult.audit.nonNormalizedEmails).toBe(1);
      expect(blockedResult.audit.whitespaceOnlyEmails).toBe(1);
      expect(blockedResult.blockers.length).toBe(3);

      const indexes = await User.collection.indexes();
      expect(indexes.some((i) => i.name === PREP_EMAIL_UNIQUE_INDEX_NAME)).toBe(false);
    });

    it("allows historical email: null/empty rows, creates uniq_user_nonempty_email_prep on clean DB, and blocks concurrent duplicate registrations", async () => {
      // Historical POS customers without email (null & "") must NOT block transitional partial index
      await User.collection.insertMany([
        {
          username: "Legacy POS Null 1",
          email: null,
          phone: "9810000001",
          role: "CUSTOMER",
          isVerified: true,
          isActive: true,
          emailVerifiedAt: null,
        },
        {
          username: "Legacy POS Null 2",
          email: null,
          phone: "9810000002",
          role: "CUSTOMER",
          isVerified: true,
          isActive: true,
          emailVerifiedAt: null,
        },
        {
          username: "Legacy Empty",
          email: "",
          phone: "9810000003",
          role: "CUSTOMER",
          isVerified: true,
          isActive: true,
          emailVerifiedAt: null,
        },
        {
          username: "Existing Verified",
          email: "verified@storra.test",
          phone: "9810000004",
          role: "CUSTOMER",
          isVerified: true,
          isActive: true,
          emailVerifiedAt: new Date(),
        },
      ]);

      const dryRun = await ensurePrepEmailUniqueIndex({ apply: false });
      expect(dryRun.status).toBe("eligible");
      expect(dryRun.applied).toBe(false);
      expect(dryRun.audit.nullOrMissingEmails).toBe(2);
      expect(dryRun.audit.emptyStringEmails).toBe(1);
      expect(formatPrepEmailIndexSummary(dryRun)).toContain("eligible");

      const applied = await ensurePrepEmailUniqueIndex({ apply: true });
      expect(applied.status).toBe("applied");
      expect(applied.applied).toBe(true);
      expect(applied.existingIndexes.hasPrepPartialUnique).toBe(true);
      expect(applied.existingIndexes.hasPhoneUnique).toBe(true);

      // Re-run is idempotent
      const secondRun = await ensurePrepEmailUniqueIndex({ apply: true });
      expect(secondRun.status).toBe("already_present");
      expect(secondRun.applied).toBe(false);

      // Concurrent SMS registrations with SAME email and DIFFERENT phones:
      // exactly 1 succeeds (201) and 1 fails cleanly with 409 DUPLICATE
      mockMsg91PhoneLookup();
      const c1 = await bootstrapCsrfAgent(appCtx.app);
      const c2 = await bootstrapCsrfAgent(appCtx.app);

      const [res1, res2] = await Promise.all([
        c1.agent
          .post("/api/auth/mobile/register")
          .set("Origin", c1.origin)
          .set("X-CSRF-Token", c1.csrfToken)
          .set("X-Forwarded-For", nextTestIp())
          .send({
            name: "Race User One",
            email: "race.shared@storra.test",
            phone: "9822000001",
            accessToken: "919822000001",
          }),
        c2.agent
          .post("/api/auth/mobile/register")
          .set("Origin", c2.origin)
          .set("X-CSRF-Token", c2.csrfToken)
          .set("X-Forwarded-For", nextTestIp())
          .send({
            name: "Race User Two",
            email: "  RACE.SHARED@STORRA.TEST ",
            phone: "9822000002",
            accessToken: "919822000002",
          }),
      ]);

      const statuses = [res1.status, res2.status].sort((a, b) => a - b);
      expect(statuses).toEqual([201, 409]);

      const failed = res1.status === 409 ? res1 : res2;
      expect(failed.body.code).toBe("DUPLICATE");

      const savedRaceUsers = await User.find({ email: "race.shared@storra.test" }).lean();
      expect(savedRaceUsers).toHaveLength(1);
      expect(savedRaceUsers[0].emailVerifiedAt).toBeNull();
    });
  });

  describe("3. Offline POS customer creation & existing customer order placement", () => {
    const seedPosActorAndProduct = async (stock = 10) => {
      const admin = await User.create({
        username: "Counter Admin",
        email: "pos.admin@storra.test",
        phone: "9850000001",
        role: "ADMIN",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      });
      const category = await Category.create({
        code: "HERBS",
        name: "Herbs",
        isActive: true,
      });
      const product = await Product.create({
        code: `SKU-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        name: "Ashwagandha Churna",
        description: "Pure herbal powder",
        price: 450,
        stock,
        isActive: true,
        categoryId: category._id,
      });
      const adminJwt = jwt.sign(
        { id: admin.id, email: admin.email, role: "ADMIN", tokenVersion: 0 },
        env.JWT_SECRET,
        { expiresIn: "1h" },
      );
      return { admin, product, adminJwt };
    };

    it("rejects POS newCustomer creation without valid email or phone, leaving zero user/order writes", async () => {
      const { admin, product, adminJwt } = await seedPosActorAndProduct();
      const { csrfToken, origin } = await bootstrapCsrfAgent(appCtx.app);
      const itemPayload = [{ productId: product.id, quantity: 1 }];

      const invalidNewCustomers: Array<Record<string, unknown>> = [
        { username: "Walkin One", phone: "9860000001" },
        { username: "Walkin One", phone: "9860000001", email: null },
        { username: "Walkin One", phone: "9860000001", email: "" },
        { username: "Walkin One", phone: "9860000001", email: "   " },
        { username: "Walkin One", phone: "9860000001", email: "bad-email" },
        { username: "Walkin One", email: "walkin@storra.test" },
        { username: "Walkin One", phone: null, email: "walkin@storra.test" },
        { username: "Walkin One", phone: "", email: "walkin@storra.test" },
        { username: "Walkin One", phone: "12345", email: "walkin@storra.test" },
      ];

      for (const newCustomer of invalidNewCustomers) {
        const res = await request(appCtx.app)
          .post("/api/order/admin-order/place")
          .set("Origin", origin)
          .set("Cookie", [`jwt=${adminJwt}`, `csrfToken=${csrfToken}`])
          .set("X-CSRF-Token", csrfToken)
          .set("X-Forwarded-For", nextTestIp())
          .send({
            newCustomer,
            items: itemPayload,
            address: { fullAddress: "", city: "", state: "", zipCode: "", country: "India" },
            paymentMethod: "CASH",
          });
        expect(res.status).toBe(400);
      }

      // Only the seeded admin exists
      const users = await User.find({ _id: { $ne: admin._id } }).lean();
      expect(users).toHaveLength(0);
      expect(await Order.countDocuments()).toBe(0);
    });

    it("creates normalized POS customer with emailVerifiedAt: null, places order, handles conflicts, and rejects concurrent duplicates", async () => {
      const { product, adminJwt } = await seedPosActorAndProduct(10);
      await ensurePrepEmailUniqueIndex({ apply: true });
      jest.spyOn(globalThis, "fetch").mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: "success" }),
      } as globalThis.Response);

      const { csrfToken, origin } = await bootstrapCsrfAgent(appCtx.app);

      // 1. Valid POS new customer creation (normalizes +91 phone & mixed-case email, sets emailVerifiedAt: null)
      const createRes = await request(appCtx.app)
        .post("/api/order/admin-order/place")
        .set("Origin", origin)
        .set("Cookie", [`jwt=${adminJwt}`, `csrfToken=${csrfToken}`])
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({
          newCustomer: {
            username: "  Ramesh Menon ",
            phone: "+91 98611-22334",
            email: "  Ramesh.Menon@Storra.TEST ",
          },
          items: [{ productId: product.id, quantity: 2 }],
          address: { fullAddress: "", city: "", state: "", zipCode: "", country: "India" },
          paymentMethod: "CASH",
          paymentNote: "Counter cash",
        });

      expect(createRes.status).toBe(201);
      expect(createRes.body.order?.paymentMethod).toBe("CASH");
      expect(createRes.body.order?.finalAmount).toBe(900);
      expect(createRes.body.customer?.email).toBe("ramesh.menon@storra.test");

      const posUser = await User.findOne({ phone: "9861122334" }).lean();
      expect(posUser).toBeTruthy();
      expect(posUser?.email).toBe("ramesh.menon@storra.test");
      expect(posUser?.role).toBe("CUSTOMER");
      expect(posUser?.isVerified).toBe(true);
      expect(posUser?.emailVerifiedAt).toBeNull();

      const updatedProduct = await Product.findById(product._id).lean();
      expect(updatedProduct?.stock).toBe(8);

      // 2. Duplicate email against existing CUSTOMER returns 409 CUSTOMER_ALREADY_EXISTS for modal selection
      const dupEmailRes = await request(appCtx.app)
        .post("/api/order/admin-order/place")
        .set("Origin", origin)
        .set("Cookie", [`jwt=${adminJwt}`, `csrfToken=${csrfToken}`])
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({
          newCustomer: {
            username: "Duplicate Email Attempt",
            phone: "9861199999",
            email: "ramesh.menon@storra.test",
          },
          items: [{ productId: product.id, quantity: 1 }],
          paymentMethod: "POD",
        });

      expect(dupEmailRes.status).toBe(409);
      expect(dupEmailRes.body.code).toBe("CUSTOMER_ALREADY_EXISTS");
      expect(dupEmailRes.body.conflictField).toBe("email");
      expect(dupEmailRes.body.existingCustomer?.id).toBe(String(posUser!._id));

      // 3. Duplicate email against ADMIN returns 409 NON_CUSTOMER_CONFLICT without exposing admin in existingCustomer
      const dupAdminRes = await request(appCtx.app)
        .post("/api/order/admin-order/place")
        .set("Origin", origin)
        .set("Cookie", [`jwt=${adminJwt}`, `csrfToken=${csrfToken}`])
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({
          newCustomer: {
            username: "Admin Email Collision",
            phone: "9861188888",
            email: "pos.admin@storra.test",
          },
          items: [{ productId: product.id, quantity: 1 }],
          paymentMethod: "CASH",
        });

      expect(dupAdminRes.status).toBe(409);
      expect(dupAdminRes.body.code).toBe("NON_CUSTOMER_CONFLICT");
      expect(dupAdminRes.body.existingCustomer).toBeUndefined();

      // 4. Concurrent duplicate POS customer creation under uniq_user_nonempty_email_prep
      const [p1, p2] = await Promise.all([
        request(appCtx.app)
          .post("/api/order/admin-order/place")
          .set("Origin", origin)
          .set("Cookie", [`jwt=${adminJwt}`, `csrfToken=${csrfToken}`])
          .set("X-CSRF-Token", csrfToken)
          .set("X-Forwarded-For", nextTestIp())
          .send({
            newCustomer: {
              username: "Concurrent POS A",
              phone: "9861177771",
              email: "pos.concurrent@storra.test",
            },
            items: [{ productId: product.id, quantity: 1 }],
            paymentMethod: "CASH",
          }),
        request(appCtx.app)
          .post("/api/order/admin-order/place")
          .set("Origin", origin)
          .set("Cookie", [`jwt=${adminJwt}`, `csrfToken=${csrfToken}`])
          .set("X-CSRF-Token", csrfToken)
          .set("X-Forwarded-For", nextTestIp())
          .send({
            newCustomer: {
              username: "Concurrent POS B",
              phone: "9861177772",
              email: "  POS.CONCURRENT@Storra.TEST ",
            },
            items: [{ productId: product.id, quantity: 1 }],
            paymentMethod: "CASH",
          }),
      ]);

      expect([p1.status, p2.status].sort((a, b) => a - b)).toEqual([201, 409]);
      expect(await User.countDocuments({ email: "pos.concurrent@storra.test" })).toBe(1);
    });

    it("continues allowing POS orders for selected existing customers (including legacy pre-migration customers with email: null)", async () => {
      const { product, adminJwt } = await seedPosActorAndProduct(10);
      jest.spyOn(globalThis, "fetch").mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: "success" }),
      } as globalThis.Response);

      const legacyNullCustomer = await User.create({
        username: "Legacy Walkin",
        email: null,
        phone: "9870000001",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: null,
      });

      const emailCustomer = await User.create({
        username: "Regular Walkin",
        email: "regular.walkin@storra.test",
        phone: "9870000002",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: null,
      });

      const { csrfToken, origin } = await bootstrapCsrfAgent(appCtx.app);

      // Existing legacy customer with email: null
      const legacyOrderRes = await request(appCtx.app)
        .post("/api/order/admin-order/place")
        .set("Origin", origin)
        .set("Cookie", [`jwt=${adminJwt}`, `csrfToken=${csrfToken}`])
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({
          customerId: legacyNullCustomer.id,
          items: [{ productId: product.id, quantity: 1 }],
          address: { fullAddress: "", city: "", state: "", zipCode: "", country: "India" },
          paymentMethod: "POD",
        });

      expect(legacyOrderRes.status).toBe(201);
      expect(legacyOrderRes.body.customer?.id).toBe(legacyNullCustomer.id);
      expect(legacyOrderRes.body.order?.paymentMethod).toBe("POD");

      // Existing customer with email
      const regularOrderRes = await request(appCtx.app)
        .post("/api/order/admin-order/place")
        .set("Origin", origin)
        .set("Cookie", [`jwt=${adminJwt}`, `csrfToken=${csrfToken}`])
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({
          customerId: emailCustomer.id,
          items: [{ productId: product.id, quantity: 2 }],
          address: {
            fullAddress: "10 MG Road",
            city: "Kochi",
            state: "Kerala",
            zipCode: "682001",
            country: "India",
          },
          paymentMethod: "CASH",
        });

      expect(regularOrderRes.status).toBe(201);
      expect(regularOrderRes.body.customer?.id).toBe(emailCustomer.id);
      expect(regularOrderRes.body.order?.finalAmount).toBe(900);

      // No extra user accounts created
      expect(await User.countDocuments({ role: "CUSTOMER" })).toBe(2);
      expect(await Order.countDocuments()).toBe(2);
    });
  });
});

