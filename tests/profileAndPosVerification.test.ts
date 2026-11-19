import jwt from "jsonwebtoken";
import request from "supertest";
import { env } from "../src/config/env";
import { createApp } from "../src/server";
import {
  AppSetting,
  AuditLog,
  Category,
  EmailOutbox,
  Order,
  OtpChallenge,
  OtpRateLimit,
  Product,
  StaffProfile,
  User,
} from "../src/models/mongoose";
import { generateToken } from "../src/config/tokens";
import { CUSTOMER_EMAIL_OTP_FLAG_KEY } from "../src/utils/featureFlags";
import { OTP_RESEND_COOLDOWN_MS } from "../src/services/otp.service";
import { decryptOutboxPayload } from "../src/utils/otpCrypto";
import { bootstrapCsrfAgent, nextTestIp, parseSetCookies } from "./helpers/httpHelper";
import { clearTestDb, startTestDb, stopTestDb } from "./helpers/testDb";

describe("PR 2 — Authenticated Profile Email Verification & POS Counter Email Verification", () => {
  let appCtx: ReturnType<typeof createApp>;

  beforeAll(async () => {
    await startTestDb();
    await Promise.all([
      User.init(),
      StaffProfile.init(),
      Category.init(),
      Product.init(),
      Order.init(),
      AuditLog.init(),
      AppSetting.init(),
      OtpChallenge.init(),
      OtpRateLimit.init(),
      EmailOutbox.init(),
    ]);
    appCtx = createApp();
  });

  afterEach(async () => {
    jest.restoreAllMocks();
    await clearTestDb();
  });

  afterAll(async () => {
    if (appCtx) {
      appCtx.stopSocketRecheck();
      await new Promise<void>((resolve) => appCtx.io.close(() => resolve()));
    }
    await stopTestDb();
  });

  const signJwtFor = (user: { id: string; email?: string | null; role: string; tokenVersion?: number }) =>
    jwt.sign(
      {
        id: user.id,
        email: user.email ?? "",
        role: user.role,
        tokenVersion: user.tokenVersion ?? 0,
      },
      env.JWT_SECRET,
      { expiresIn: "1h" },
    );

  const issueRealSessionJwt = async (userId: string, role: string, email: string, tokenVersion = 0) => {
    let jwtCookie = "";
    const fakeRes = {
      clearCookie() {
        return this;
      },
      cookie(name: string, val: string) {
        if (name === "jwt") jwtCookie = val;
        return this;
      },
    } as unknown as Parameters<typeof generateToken>[1];
    await generateToken({ id: userId, role, email, tokenVersion }, fakeRes);
    return jwtCookie;
  };

  const readOtpForChallenge = async (challengeId: string): Promise<string> => {
    const outbox = await EmailOutbox.findOne({ challengeId }).lean();
    expect(outbox?.encryptedPayload).toBeTruthy();
    return decryptOutboxPayload(outbox!.encryptedPayload!).variables.OTP;
  };

  describe("1. Authenticated customer/admin profile email verification & updates", () => {
    it("allows legacy customer with missing email to add & verify email without falsely claiming phone verification, and blocks duplicate emails", async () => {
      const legacyCustomer = await User.create({
        username: "Legacy NoEmail",
        email: null,
        phone: "9820000001",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: null,
        posActivationRequired: true,
        tokenVersion: 0,
      });
      await User.create({
        username: "Protected Admin",
        email: "taken.admin@storra.test",
        phone: "9820000002",
        role: "ADMIN",
        isActive: true,
        isVerified: true,
      });

      const custJwt = await issueRealSessionJwt(legacyCustomer.id, "CUSTOMER", "", 0);
      const { origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

      // 1. Global duplicate email across roles blocked cleanly with 409
      const dupRes = await request(appCtx.app)
        .post("/api/user/profile/request-update")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${custJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ newEmail: "TAKEN.ADMIN@storra.test" });
      expect(dupRes.status).toBe(409);

      // 2. Request OTP to add first verified email
      const reqRes = await request(appCtx.app)
        .post("/api/user/profile/request-update")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${custJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ newEmail: "  Added.Email@Storra.TEST ", newUsername: "Updated Legacy" });
      expect(reqRes.status).toBe(200);
      expect(reqRes.body.challengeId).toBeTruthy();

      // Prior to OTP verify, DB user STILL has emailVerifiedAt: null
      const preVerify = await User.findById(legacyCustomer.id).lean();
      expect(preVerify?.emailVerifiedAt).toBeNull();

      // 3. Another user cannot verify this challenge (bound to legacyCustomer.id)
      const otherJwt = signJwtFor({ id: (await User.findOne({ role: "ADMIN" }))!.id, email: "taken.admin@storra.test", role: "ADMIN" });
      const otp = await readOtpForChallenge(reqRes.body.challengeId);
      const crossUserVerify = await request(appCtx.app)
        .post("/api/user/profile/verify-update")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${otherJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ otp, challengeId: reqRes.body.challengeId });
      expect(crossUserVerify.status).toBe(401);

      // 4. Wrong OTP rejected cleanly without updating user
      const badOtp = otp === "123456" ? "654321" : "123456";
      const wrongRes = await request(appCtx.app)
        .post("/api/user/profile/verify-update")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${custJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ otp: badOtp, challengeId: reqRes.body.challengeId });
      expect(wrongRes.status).toBe(401);
      expect(wrongRes.body.attemptsRemaining).toBe(4);

      // 5. Correct OTP completes update transactionally, increments tokenVersion, rotates cookies, clears posActivationRequired, keeps valid phone
      const verifyOk = await request(appCtx.app)
        .post("/api/user/profile/verify-update")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${custJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ otp, challengeId: reqRes.body.challengeId });
      expect(verifyOk.status).toBe(200);
      expect(verifyOk.body.user?.email).toBe("added.email@storra.test");
      expect(verifyOk.body.user?.emailVerifiedAt).toBeTruthy();
      expect(verifyOk.body.user?.posActivationRequired).toBe(false);

      const saved = await User.findById(legacyCustomer.id).lean();
      expect(saved?.email).toBe("added.email@storra.test");
      expect(saved?.phone).toBe("9820000001");
      expect(saved?.emailVerifiedAt).toBeTruthy();
      expect(saved?.posActivationRequired).toBe(false);
      expect(saved?.tokenVersion).toBe(1);

      const rotatedCookies = parseSetCookies(verifyOk.headers["set-cookie"]);
      expect(rotatedCookies.jwt?.value).toBeTruthy();
      expect(rotatedCookies.refreshToken?.value).toBeTruthy();

      // GET /api/user/profile with new rotated JWT exposes emailVerifiedAt & posActivationRequired
      const meRes = await request(appCtx.app)
        .get("/api/user/profile")
        .set("Cookie", [`jwt=${rotatedCookies.jwt.value}`]);
      expect(meRes.status).toBe(200);
      expect(meRes.body.users?.emailVerifiedAt).toBeTruthy();
      expect(meRes.body.users?.posActivationRequired).toBe(false);
    });

    it("supports admin profile resend-otp & verification via /api/admin/adminProfile/*", async () => {
      const admin = await User.create({
        username: "Store Owner",
        email: "owner.old@storra.test",
        phone: "9820000099",
        role: "ADMIN",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: null,
        tokenVersion: 0,
      });

      const adminJwt = await issueRealSessionJwt(admin.id, "ADMIN", admin.email!, 0);
      const { origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

      const reqRes = await request(appCtx.app)
        .post("/api/admin/adminProfile/request-update")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${adminJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ newEmail: "owner.old@storra.test", newUsername: "Store Owner" });
      expect(reqRes.status).toBe(200);

      await OtpChallenge.updateOne(
        { challengeId: reqRes.body.challengeId },
        { $set: { lastSentAt: new Date(Date.now() - (OTP_RESEND_COOLDOWN_MS + 5000)) } },
      );
      await OtpRateLimit.updateOne(
        { key: "cooldown:profile_update:owner.old@storra.test" },
        { $set: { resetAt: new Date(Date.now() - 1000) } },
      );

      const resendRes = await request(appCtx.app)
        .post("/api/admin/adminProfile/resend-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${adminJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ challengeId: reqRes.body.challengeId });
      expect(resendRes.status).toBe(200);

      const otp = await readOtpForChallenge(resendRes.body.challengeId);
      const verifyRes = await request(appCtx.app)
        .post("/api/admin/adminProfile/verify-update")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${adminJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ otp, challengeId: resendRes.body.challengeId });
      expect(verifyRes.status).toBe(200);

      const updated = await User.findById(admin.id).lean();
      expect(updated?.emailVerifiedAt).toBeTruthy();
      expect(updated?.tokenVersion).toBe(0); // same email verified -> no tokenVersion bump required
    });
  });

  describe("2. POS counter email verification & skipped activation policy", () => {
    const seedPosInventory = async () => {
      const admin = await User.create({
        username: "POS Cashier",
        email: "cashier@storra.test",
        phone: "9830001001",
        role: "ADMIN",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      });
      const staffNoPerm = await User.create({
        username: "Viewer Staff",
        email: "viewer@storra.test",
        phone: "9830001002",
        role: "STAFF",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      });
      await StaffProfile.create({
        userId: staffNoPerm._id,
        managedBy: admin._id,
        permissions: ["ORDER_VIEW"],
        isActive: true,
      });
      const staffWithPerm = await User.create({
        username: "Counter Staff",
        email: "counter.staff@storra.test",
        phone: "9830001003",
        role: "STAFF",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      });
      await StaffProfile.create({
        userId: staffWithPerm._id,
        managedBy: admin._id,
        permissions: ["ORDER_CREATE"],
        isActive: true,
      });
      const category = await Category.create({ code: "POSCAT", name: "POS Category", isActive: true });
      const product = await Product.create({
        code: "POSSKU-1",
        name: "POS Counter Oil",
        price: 500,
        stock: 20,
        isActive: true,
        categoryId: category._id,
      });
      return {
        admin,
        adminJwt: signJwtFor({ id: admin.id, email: admin.email, role: "ADMIN" }),
        staffNoPermJwt: signJwtFor({ id: staffNoPerm.id, email: staffNoPerm.email, role: "STAFF" }),
        staffWithPermJwt: signJwtFor({ id: staffWithPerm.id, email: staffWithPerm.email, role: "STAFF" }),
        product,
      };
    };

    it("enforces ORDER_CREATE RBAC, allows unblocked POS order when skipped, blocks Email OTP login until counter verified, and activates cleanly upon pos_counter_verify", async () => {
      await AppSetting.create({ key: CUSTOMER_EMAIL_OTP_FLAG_KEY, value: true });
      jest.spyOn(globalThis, "fetch").mockImplementation(async (url, init) => {
        const urlStr = String(url);
        if (urlStr.includes("widget/verifyAccessToken")) {
          const reqBody = JSON.parse(String(init?.body ?? "{}")) as {
            "access-token"?: string;
          };
          return {
            ok: true,
            status: 200,
            text: async () =>
              JSON.stringify({
                type: "success",
                data: { mobile: reqBody["access-token"] || "919840001111" },
              }),
          } as globalThis.Response;
        }
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ status: "success" }),
        } as globalThis.Response;
      });

      const { adminJwt, staffNoPermJwt, staffWithPermJwt, product } = await seedPosInventory();
      const { origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

      // 1. Place offline POS order creating new customer (counter email verification skipped)
      const orderRes = await request(appCtx.app)
        .post("/api/order/admin-order/place")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${adminJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({
          newCustomer: {
            username: "Walkin Counter Customer",
            phone: "9840001111",
            email: "walkin.counter@storra.test",
          },
          items: [{ productId: product.id, quantity: 1 }],
          paymentMethod: "CASH",
        });

      expect(orderRes.status).toBe(201);
      expect(orderRes.body.customer?.emailVerifiedAt).toBeNull();
      expect(orderRes.body.customer?.posActivationRequired).toBe(true);

      const walkinCustomerId = orderRes.body.customer.id as string;
      const dbWalkin = await User.findById(walkinCustomerId).lean();
      expect(dbWalkin?.emailVerifiedAt).toBeNull();
      expect(dbWalkin?.posActivationRequired).toBe(true);

      // 2. While counter verification is skipped, customer CANNOT activate Email OTP login
      const customerLoginAttempt = await request(appCtx.app)
        .post("/api/auth/customer/login/request-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: "walkin.counter@storra.test" });
      expect(customerLoginAttempt.status).toBe(403);
      expect(customerLoginAttempt.body.code).toBe("EMAIL_NOT_VERIFIED");
      expect(
        await OtpChallenge.countDocuments({
          email: "walkin.counter@storra.test",
          purpose: "customer_login",
        }),
      ).toBe(0);

      // Knowing the phone number via SMS prep login does NOT stamp emailVerifiedAt or clear posActivationRequired
      const smsLogin = await request(appCtx.app)
        .post("/api/auth/mobile/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ phone: "9840001111", accessToken: "919840001111" });
      expect(smsLogin.status).toBe(200);
      const afterSmsUser = await User.findById(walkinCustomerId).lean();
      expect(afterSmsUser?.emailVerifiedAt).toBeNull();
      expect(afterSmsUser?.posActivationRequired).toBe(true);

      // 3. RBAC: customer and STAFF without ORDER_CREATE denied on pos-verify routes
      const custToken = signJwtFor({ id: walkinCustomerId, email: "walkin.counter@storra.test", role: "CUSTOMER" });
      for (const unauthorizedToken of [custToken, staffNoPermJwt]) {
        const denied = await request(appCtx.app)
          .post("/api/order/admin-order/pos-verify/request-otp")
          .set("Origin", origin)
          .set("X-CSRF-Token", csrfToken)
          .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${unauthorizedToken}`])
          .set("X-Forwarded-For", nextTestIp())
          .send({ customerId: walkinCustomerId });
        expect(denied.status).toBe(403);
      }

      // 4. Staff with ORDER_CREATE initiates pos_counter_verify (mismatched submitted email rejected 400)
      const emailMismatch = await request(appCtx.app)
        .post("/api/order/admin-order/pos-verify/request-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${staffWithPermJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ customerId: walkinCustomerId, email: "other@storra.test" });
      expect(emailMismatch.status).toBe(400);
      expect(emailMismatch.body.code).toBe("EMAIL_MISMATCH");

      const posReq = await request(appCtx.app)
        .post("/api/order/admin-order/pos-verify/request-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${staffWithPermJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ customerId: walkinCustomerId });
      expect(posReq.status).toBe(200);
      expect(posReq.body.alreadyVerified).toBe(false);
      expect(posReq.body.challengeId).toBeTruthy();

      const posOtp = await readOtpForChallenge(posReq.body.challengeId);

      // Cross-purpose attack: submitting pos_counter_verify challenge against customer_login fails!
      const crossPurpose = await request(appCtx.app)
        .post("/api/auth/customer/login/verify-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({
          email: "walkin.counter@storra.test",
          challengeId: posReq.body.challengeId,
          otp: posOtp,
        });
      expect(crossPurpose.status).toBe(401);

      // 5. Verify POS OTP -> stamps emailVerifiedAt, clears posActivationRequired, records audit log
      const posVerifyOk = await request(appCtx.app)
        .post("/api/order/admin-order/pos-verify/verify-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${staffWithPermJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({
          customerId: walkinCustomerId,
          challengeId: posReq.body.challengeId,
          otp: posOtp,
        });
      expect(posVerifyOk.status).toBe(200);
      expect(posVerifyOk.body.customer?.emailVerifiedAt).toBeTruthy();
      expect(posVerifyOk.body.customer?.posActivationRequired).toBe(false);

      const activatedCustomer = await User.findById(walkinCustomerId).lean();
      expect(activatedCustomer?.emailVerifiedAt).toBeTruthy();
      expect(activatedCustomer?.posActivationRequired).toBe(false);

      const auditEntry = await AuditLog.findOne({
        action: "POS_CUSTOMER_EMAIL_VERIFIED",
        entityId: walkinCustomerId,
      }).lean();
      expect(auditEntry).toBeTruthy();

      // 6. Now standard customer Email OTP login issues a REAL (non-decoy) challenge and succeeds!
      const nowLoginReq = await request(appCtx.app)
        .post("/api/auth/customer/login/request-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: "walkin.counter@storra.test" });
      expect(nowLoginReq.status).toBe(200);
      const realChallenge = await OtpChallenge.findOne({
        challengeId: nowLoginReq.body.challengeId,
      }).lean();
      expect(realChallenge?.isDecoy).toBe(false);

      const loginOtp = await readOtpForChallenge(nowLoginReq.body.challengeId);
      const loginVerify = await request(appCtx.app)
        .post("/api/auth/customer/login/verify-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({
          email: "walkin.counter@storra.test",
          challengeId: nowLoginReq.body.challengeId,
          otp: loginOtp,
        });
      expect(loginVerify.status).toBe(200);
      expect(loginVerify.body.user?.id).toBe(walkinCustomerId);
    });

    it("preserves historical selected-customer POS order placement intact even when customer email is unverified", async () => {
      jest.spyOn(globalThis, "fetch").mockImplementation(async (url, init) => {
        const urlStr = String(url);
        if (urlStr.includes("widget/verifyAccessToken")) {
          const reqBody = JSON.parse(String(init?.body ?? "{}")) as {
            "access-token"?: string;
          };
          return {
            ok: true,
            status: 200,
            text: async () =>
              JSON.stringify({
                type: "success",
                data: { mobile: reqBody["access-token"] || "919840001111" },
              }),
          } as globalThis.Response;
        }
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ status: "success" }),
        } as globalThis.Response;
      });

      const { adminJwt, product } = await seedPosInventory();
      const existingCustomer = await User.create({
        username: "Historical Regular",
        email: "historical@storra.test",
        phone: "9840002222",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: null,
        posActivationRequired: false,
      });

      const { origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);
      const orderRes = await request(appCtx.app)
        .post("/api/order/admin-order/place")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${adminJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({
          customerId: existingCustomer.id,
          items: [{ productId: product.id, quantity: 2 }],
          paymentMethod: "POD",
        });

      expect(orderRes.status).toBe(201);
      expect(orderRes.body.order?.finalAmount).toBe(1000);
      expect(orderRes.body.customer?.id).toBe(existingCustomer.id);
      expect(await Order.countDocuments({ userId: existingCustomer._id })).toBe(1);
    });

    it("blocks customer-ID substitution, email substitution, and cross-customer OTP replay (including duplicate legacy emails)", async () => {
      const { staffWithPermJwt } = await seedPosInventory();
      const { origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

      const custA = await User.create({
        username: "Customer Alpha",
        email: "alpha@storra.test",
        phone: "9841000001",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: null,
        posActivationRequired: true,
      });
      const custB = await User.create({
        username: "Customer Beta",
        email: "beta@storra.test",
        phone: "9841000002",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: null,
        posActivationRequired: true,
      });

      const reqA = await request(appCtx.app)
        .post("/api/order/admin-order/pos-verify/request-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${staffWithPermJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ customerId: custA.id, email: "ALPHA@storra.test" });
      expect(reqA.status).toBe(200);
      const otpA = await readOtpForChallenge(reqA.body.challengeId);

      // Customer-ID substitution on resend-otp & verify-otp rejected
      const subResend = await request(appCtx.app)
        .post("/api/order/admin-order/pos-verify/resend-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${staffWithPermJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ customerId: custB.id, challengeId: reqA.body.challengeId });
      expect(subResend.status).toBe(401);

      const subVerify = await request(appCtx.app)
        .post("/api/order/admin-order/pos-verify/verify-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${staffWithPermJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ customerId: custB.id, challengeId: reqA.body.challengeId, otp: otpA });
      expect(subVerify.status).toBe(401);

      expect((await User.findById(custA.id).lean())?.emailVerifiedAt).toBeNull();
      expect((await User.findById(custB.id).lean())?.emailVerifiedAt).toBeNull();

      // Pre-PR-3 legacy duplicate email scenario: two customers share the exact same normalized email
      const [dupA, dupB] = await User.insertMany([
        {
          username: "Legacy Duplicate A",
          email: "shared.legacy@storra.test",
          phone: "9841000011",
          role: "CUSTOMER",
          isActive: true,
          isVerified: true,
          emailVerifiedAt: null,
          posActivationRequired: true,
        },
        {
          username: "Legacy Duplicate B",
          email: "shared.legacy@storra.test",
          phone: "9841000012",
          role: "CUSTOMER",
          isActive: true,
          isVerified: true,
          emailVerifiedAt: null,
          posActivationRequired: true,
        },
      ]);

      const dupReqA = await request(appCtx.app)
        .post("/api/order/admin-order/pos-verify/request-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${staffWithPermJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ customerId: dupA.id });
      expect(dupReqA.status).toBe(200);
      const dupOtpA = await readOtpForChallenge(dupReqA.body.challengeId);

      // Cross-customer replay using dupA's challengeId + OTP for dupB MUST fail
      const replayOnB = await request(appCtx.app)
        .post("/api/order/admin-order/pos-verify/verify-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${staffWithPermJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ customerId: dupB.id, challengeId: dupReqA.body.challengeId, otp: dupOtpA });
      expect(replayOnB.status).toBe(401);
      expect((await User.findById(dupB.id).lean())?.emailVerifiedAt).toBeNull();

      // Verify dupA legitimately, then replay fails as CHALLENGE_CONSUMED
      const verifyDupA = await request(appCtx.app)
        .post("/api/order/admin-order/pos-verify/verify-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${staffWithPermJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ customerId: dupA.id, challengeId: dupReqA.body.challengeId, otp: dupOtpA });
      expect(verifyDupA.status).toBe(200);
      expect((await User.findById(dupA.id).lean())?.emailVerifiedAt).toBeTruthy();
      expect((await User.findById(dupB.id).lean())?.emailVerifiedAt).toBeNull();

      const replayAfterUse = await request(appCtx.app)
        .post("/api/order/admin-order/pos-verify/verify-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${staffWithPermJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ customerId: dupA.id, challengeId: dupReqA.body.challengeId, otp: dupOtpA });
      expect(replayAfterUse.status).toBe(401);
      expect(replayAfterUse.body.code).toBe("CHALLENGE_CONSUMED");

      // Mid-challenge DB email mutation rejects cleanly and leaves challenge unconsumed
      const reqB = await request(appCtx.app)
        .post("/api/order/admin-order/pos-verify/request-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${staffWithPermJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ customerId: custB.id });
      expect(reqB.status).toBe(200);
      const otpB = await readOtpForChallenge(reqB.body.challengeId);

      await User.updateOne({ _id: custB._id }, { $set: { email: "mutated.beta@storra.test" } });

      const emailMutatedVerify = await request(appCtx.app)
        .post("/api/order/admin-order/pos-verify/verify-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${staffWithPermJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ customerId: custB.id, challengeId: reqB.body.challengeId, otp: otpB });
      expect(emailMutatedVerify.status).toBe(401);

      const chgB = await OtpChallenge.findOne({ challengeId: reqB.body.challengeId }).lean();
      expect(chgB?.consumedAt).toBeNull();
      expect((await User.findById(custB.id).lean())?.emailVerifiedAt).toBeNull();
    });

    it("rolls back consumedAt when User update throws inside transaction for both verifyPosCustomerEmailOtp and verifyAndUpdateProfile", async () => {
      const { staffWithPermJwt } = await seedPosInventory();
      const { origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

      // 1. POS counter transaction rollback test
      const posCust = await User.create({
        username: "Rollback POS Customer",
        email: "rollback.pos@storra.test",
        phone: "9842000001",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: null,
        posActivationRequired: true,
      });

      const posReq = await request(appCtx.app)
        .post("/api/order/admin-order/pos-verify/request-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${staffWithPermJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ customerId: posCust.id });
      expect(posReq.status).toBe(200);
      const posOtp = await readOtpForChallenge(posReq.body.challengeId);

      const saveSpy = jest
        .spyOn(User.prototype, "save")
        .mockRejectedValueOnce(new Error("Simulated POS save failure"));

      const posFailRes = await request(appCtx.app)
        .post("/api/order/admin-order/pos-verify/verify-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${staffWithPermJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ customerId: posCust.id, challengeId: posReq.body.challengeId, otp: posOtp });
      expect(posFailRes.status).toBe(500);
      saveSpy.mockRestore();

      const chgAfterPosFail = await OtpChallenge.findOne({ challengeId: posReq.body.challengeId }).lean();
      expect(chgAfterPosFail?.consumedAt).toBeNull();
      expect((await User.findById(posCust.id).lean())?.emailVerifiedAt).toBeNull();

      // Immediate retry succeeds cleanly because transaction rolled back consumedAt
      const posRetryOk = await request(appCtx.app)
        .post("/api/order/admin-order/pos-verify/verify-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${staffWithPermJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ customerId: posCust.id, challengeId: posReq.body.challengeId, otp: posOtp });
      expect(posRetryOk.status).toBe(200);
      expect((await User.findById(posCust.id).lean())?.emailVerifiedAt).toBeTruthy();

      // 2. Profile update transaction rollback test
      const profCust = await User.create({
        username: "Rollback Profile User",
        email: "rollback.old@storra.test",
        phone: "9842000002",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: new Date(),
        tokenVersion: 0,
      });
      const profJwt = await issueRealSessionJwt(profCust.id, "CUSTOMER", profCust.email!, 0);

      const profReq = await request(appCtx.app)
        .post("/api/user/profile/request-update")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${profJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ newEmail: "rollback.new@storra.test" });
      expect(profReq.status).toBe(200);
      const profOtp = await readOtpForChallenge(profReq.body.challengeId);

      const updateSpy = jest
        .spyOn(User, "findByIdAndUpdate")
        .mockRejectedValueOnce(new Error("Simulated profile update failure"));

      const profFailRes = await request(appCtx.app)
        .post("/api/user/profile/verify-update")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${profJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ otp: profOtp, challengeId: profReq.body.challengeId });
      expect(profFailRes.status).toBe(500);
      updateSpy.mockRestore();

      const chgAfterProfFail = await OtpChallenge.findOne({ challengeId: profReq.body.challengeId }).lean();
      expect(chgAfterProfFail?.consumedAt).toBeNull();
      const unchangedUser = await User.findById(profCust.id).lean();
      expect(unchangedUser?.email).toBe("rollback.old@storra.test");
      expect(unchangedUser?.tokenVersion).toBe(0);

      // Immediate retry succeeds cleanly because transaction rolled back consumedAt
      const profRetryOk = await request(appCtx.app)
        .post("/api/user/profile/verify-update")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${profJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({ otp: profOtp, challengeId: profReq.body.challengeId });
      expect(profRetryOk.status).toBe(200);
      const updatedUser = await User.findById(profCust.id).lean();
      expect(updatedUser?.email).toBe("rollback.new@storra.test");
      expect(updatedUser?.tokenVersion).toBe(1);
    });
  });
});
