import crypto from "crypto";
import bcrypt from "bcryptjs";
import request from "supertest";
import { io as ioClient } from "socket.io-client";
import { env } from "../src/config/env";
import { createApp } from "../src/server";
import {
  AppSetting,
  Category,
  EmailOutbox,
  Notification,
  Order,
  OtpChallenge,
  OtpRateLimit,
  Product,
  StaffProfile,
  User,
} from "../src/models/mongoose";
import { processOutboxBatchOnce } from "../src/services/emailOutbox.service";
import { OTP_RESEND_COOLDOWN_MS } from "../src/services/otp.service";
import { decryptOutboxPayload } from "../src/utils/otpCrypto";
import { bootstrapCsrfAgent, nextTestIp, parseSetCookies } from "./helpers/httpHelper";
import { clearTestDb, startTestDb, stopTestDb } from "./helpers/testDb";

describe("PR 2 — Admin/Staff Login, Password Reset Migration, Socket Revocation & Regression", () => {
  let appCtx: ReturnType<typeof createApp>;
  let appPort = 0;

  beforeAll(async () => {
    await startTestDb();
    await Promise.all([
      User.init(),
      StaffProfile.init(),
      OtpChallenge.init(),
      OtpRateLimit.init(),
      EmailOutbox.init(),
      Category.init(),
      Product.init(),
      Order.init(),
      Notification.init(),
      AppSetting.init(),
    ]);
    appCtx = createApp();
    await new Promise<void>((resolve) => {
      appCtx.server.listen(0, "127.0.0.1", () => {
        const addr = appCtx.server.address();
        appPort = typeof addr === "object" && addr ? addr.port : 0;
        resolve();
      });
    });
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

  const readOtpForChallenge = async (challengeId: string): Promise<string> => {
    const outbox = await EmailOutbox.findOne({ challengeId }).lean();
    expect(outbox?.encryptedPayload).toBeTruthy();
    return decryptOutboxPayload(outbox!.encryptedPayload!).variables.OTP;
  };

  describe("1. Admin & Staff password-first challenge login migration", () => {
    it("rejects wrong passwords before creating any challenge, blocks cold resend/verify, enforces cross-purpose & tokenVersionSnapshot checks, and clears challenge cookie on login", async () => {
      const pwHash = await bcrypt.hash("AdminSecret@123", 10);
      const admin = await User.create({
        username: "Portal Admin",
        email: "portal.admin@storra.test",
        phone: "9850000001",
        password: pwHash,
        role: "ADMIN",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      });

      const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

      // Wrong password creates NO OtpChallenge and NO EmailOutbox
      const badPw = await agent
        .post("/api/auth/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: admin.email, password: "WrongPassword!" });
      expect(badPw.status).toBe(400);
      expect(await OtpChallenge.countDocuments()).toBe(0);
      expect(await EmailOutbox.countDocuments()).toBe(0);

      // Cold resend-otp & cold login/verify without cookie rejected with 401 CHALLENGE_MISSING
      const coldResend = await agent
        .post("/api/auth/resend-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: admin.email });
      expect(coldResend.status).toBe(401);
      expect(coldResend.body.code).toBe("CHALLENGE_MISSING");

      const coldVerify = await agent
        .post("/api/auth/login/verify")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: admin.email, otp: "123456" });
      expect(coldVerify.status).toBe(401);
      expect(coldVerify.body.code).toBe("CHALLENGE_MISSING");

      // Correct password issues authVerified=true challenge + admin_login_challenge HttpOnly cookie
      const loginStep1 = await agent
        .post("/api/auth/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: admin.email, password: "AdminSecret@123" });
      expect(loginStep1.status).toBe(200);
      expect(loginStep1.body.step).toBe("VERIFY_OTP");
      expect(loginStep1.body.challengeId).toBeTruthy();

      const step1Challenge = await OtpChallenge.findOne({
        challengeId: loginStep1.body.challengeId,
      }).lean();
      expect(step1Challenge?.authVerified).toBe(true);
      expect(step1Challenge?.purpose).toBe("admin_login");

      const firstOtp = await readOtpForChallenge(loginStep1.body.challengeId);

      // Cross-purpose check: submitting admin_login OTP to /api/auth/verify-reset-otp fails
      const wrongPurposeRes = await agent
        .post("/api/auth/verify-reset-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: admin.email, otp: firstOtp, challengeId: loginStep1.body.challengeId });
      expect(wrongPurposeRes.status).toBe(401);

      // TokenVersion bump mid-challenge rejects login/verify with 401 TOKEN_VERSION_MISMATCH
      await User.updateOne({ _id: admin._id }, { $inc: { tokenVersion: 1 } });
      const staleVersionVerify = await agent
        .post("/api/auth/login/verify")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: admin.email, otp: firstOtp });
      expect(staleVersionVerify.status).toBe(401);
      expect(staleVersionVerify.body.code).toBe("TOKEN_VERSION_MISMATCH");

      // Fresh login -> resend (after cooldown) -> verify succeeds and clears challenge cookie
      const loginStep1Fresh = await agent
        .post("/api/auth/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: admin.email, password: "AdminSecret@123" });
      expect(loginStep1Fresh.status).toBe(200);

      await OtpChallenge.updateOne(
        { challengeId: loginStep1Fresh.body.challengeId },
        { $set: { lastSentAt: new Date(Date.now() - (OTP_RESEND_COOLDOWN_MS + 5000)) } },
      );
      await OtpRateLimit.updateOne(
        { key: "cooldown:admin_login:portal.admin@storra.test" },
        { $set: { resetAt: new Date(Date.now() - 1000) } },
      );

      const resendRes = await agent
        .post("/api/auth/resend-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: admin.email, challengeId: loginStep1Fresh.body.challengeId });
      expect(resendRes.status).toBe(200);
      expect(resendRes.body.challengeId).not.toBe(loginStep1Fresh.body.challengeId);

      const finalOtp = await readOtpForChallenge(resendRes.body.challengeId);
      const verifyOk = await agent
        .post("/api/auth/login/verify")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: admin.email, otp: finalOtp });
      expect(verifyOk.status).toBe(200);
      expect(verifyOk.body.role).toBe("ADMIN");

      const cookies = parseSetCookies(verifyOk.headers["set-cookie"]);
      expect(cookies.jwt?.value).toBeTruthy();
      expect(cookies.refreshToken?.value).toBeTruthy();
      expect(cookies.admin_login_challenge?.value).toBe("");
    });

    it("rechecks StaffProfile.isActive immediately before issuing cookies on /api/auth/login/verify", async () => {
      const pwHash = await bcrypt.hash("StaffPass@123", 10);
      const staff = await User.create({
        username: "Live Staff",
        email: "live.staff@storra.test",
        phone: "9850000010",
        password: pwHash,
        role: "STAFF",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      });
      const profile = await StaffProfile.create({
        userId: staff._id,
        managedBy: staff._id,
        permissions: ["ORDER_VIEW"],
        isActive: true,
      });

      const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);
      const step1 = await agent
        .post("/api/auth/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: staff.email, password: "StaffPass@123" });
      expect(step1.status).toBe(200);
      const staffChallenge = await OtpChallenge.findOne({
        challengeId: step1.body.challengeId,
      }).lean();
      expect(staffChallenge?.purpose).toBe("admin_login");

      const otp = await readOtpForChallenge(step1.body.challengeId);

      // Admin suspends StaffProfile BEFORE staff completes OTP step 2
      await StaffProfile.updateOne({ _id: profile._id }, { $set: { isActive: false } });

      const step2 = await agent
        .post("/api/auth/login/verify")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: staff.email, otp });
      expect(step2.status).toBe(403);
      expect(step2.body.code).toBe("ACCOUNT_DEACTIVATED");
    });

    it("blocks CUSTOMER accounts with 403 ROLE_RESTRICTED on /api/auth/login and issues zero challenges", async () => {
      const pwHash = await bcrypt.hash("LegacyCustomerPw@123", 10);
      await User.create({
        username: "Legacy Customer With Password",
        email: "legacy.pw.cust@storra.test",
        phone: "9850000019",
        password: pwHash,
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
      });

      const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);
      const res = await agent
        .post("/api/auth/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: "legacy.pw.cust@storra.test", password: "LegacyCustomerPw@123" });

      expect(res.status).toBe(403);
      expect(res.body.code).toBe("ROLE_RESTRICTED");
      expect(await OtpChallenge.countDocuments()).toBe(0);
      expect(await EmailOutbox.countDocuments()).toBe(0);
    });
  });

  describe("2. Password reset migration (single-use JTI, socket revocation & decoy CUSTOMER protection)", () => {
    it("completes staff/admin reset with single-use resetTokenJti, disconnects sockets, prevents replay, and preserves customer legacy hash via decoy", async () => {
      const staff = await User.create({
        username: "Resettable Staff",
        email: "reset.staff@storra.test",
        phone: "9850000020",
        password: await bcrypt.hash("OldStaffPass@123", 10),
        role: "STAFF",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      });
      await StaffProfile.create({
        userId: staff._id,
        managedBy: staff._id,
        permissions: ["ORDER_VIEW"],
        isActive: true,
      });

      const legacyCustomerHash = "$2a$10$legacyCustomerPasswordHashKeptInPr2Only";
      const customerWithLegacyPw = await User.create({
        username: "Customer With Legacy Hash",
        email: "cust.legacy.pw@storra.test",
        phone: "9850000021",
        password: legacyCustomerHash,
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
      });

      const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

      // 1. CUSTOMER gets generic 200 decoy on /forgot-password without sending email or mutating legacy hash
      const fetchSpy = jest.spyOn(globalThis, "fetch").mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: "success" }),
      } as globalThis.Response);

      const custForgot = await agent
        .post("/api/auth/forgot-password")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: customerWithLegacyPw.email });
      expect(custForgot.status).toBe(200);
      await processOutboxBatchOnce();
      expect(fetchSpy).not.toHaveBeenCalled();

      // 2. Staff logs in to open an active WebSocket session before resetting password
      const preResetStep1 = await agent
        .post("/api/auth/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: staff.email, password: "OldStaffPass@123" });
      const loginOtp = await readOtpForChallenge(preResetStep1.body.challengeId);
      const preResetStep2 = await agent
        .post("/api/auth/login/verify")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: staff.email, otp: loginOtp });
      const activeJwt = parseSetCookies(preResetStep2.headers["set-cookie"]).jwt.value;

      const sock = ioClient(`http://127.0.0.1:${appPort}`, {
        transports: ["websocket"],
        extraHeaders: { Cookie: `jwt=${activeJwt}`, "X-Forwarded-For": "203.0.113.50" },
        reconnection: false,
      });
      await new Promise<void>((resolve, reject) => {
        sock.on("connect", () => resolve());
        sock.on("connect_error", reject);
      });
      const sockDisconnected = new Promise<{ reason: string; revokedReason?: string }>((resolve) => {
        let revokedReason: string | undefined;
        sock.on("session-revoked", (p: { reason?: string }) => {
          revokedReason = p?.reason;
        });
        sock.on("disconnect", (reason) => resolve({ reason, revokedReason }));
      });

      // 3. Staff initiates password_reset, resends after cooldown, verifies OTP, and resets password once
      const forgotRes = await agent
        .post("/api/auth/forgot-password")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: staff.email });
      expect(forgotRes.status).toBe(200);

      await OtpChallenge.updateOne(
        { challengeId: forgotRes.body.challengeId },
        { $set: { lastSentAt: new Date(Date.now() - (OTP_RESEND_COOLDOWN_MS + 5000)) } },
      );
      await OtpRateLimit.updateOne(
        { key: "cooldown:password_reset:reset.staff@storra.test" },
        { $set: { resetAt: new Date(Date.now() - 1000) } },
      );

      const resendResetRes = await agent
        .post("/api/auth/forgot-password/resend-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: staff.email, challengeId: forgotRes.body.challengeId });
      expect(resendResetRes.status).toBe(200);

      const resetOtp = await readOtpForChallenge(resendResetRes.body.challengeId);
      const verifyResetRes = await agent
        .post("/api/auth/verify-reset-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({
          email: staff.email,
          otp: resetOtp,
          challengeId: resendResetRes.body.challengeId,
        });
      expect(verifyResetRes.status).toBe(200);
      const resetCookieVal = parseSetCookies(verifyResetRes.headers["set-cookie"]).reset_token.value;

      const resetRes = await request(appCtx.app)
        .post("/api/auth/reset-password")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .set("Cookie", [`csrfToken=${csrfToken}`, `reset_token=${resetCookieVal}`])
        .send({ newPassword: "BrandNewPassword@99" });
      expect(resetRes.status).toBe(200);

      const disc = await sockDisconnected;
      expect(disc.revokedReason).toBe("PASSWORD_RESET");
      sock.close();

      // Replaying the same reset_token cookie must fail (RESET_TOKEN_USED)
      const replayReset = await request(appCtx.app)
        .post("/api/auth/reset-password")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .set("Cookie", [`csrfToken=${csrfToken}`, `reset_token=${resetCookieVal}`])
        .send({ newPassword: "ThirdPassword@99" });
      expect(replayReset.status).toBe(401);
      expect(replayReset.body.code).toBe("RESET_TOKEN_USED");

      // New password logs in cleanly; customer legacy password hash remained untouched
      const postResetLogin = await agent
        .post("/api/auth/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: staff.email, password: "BrandNewPassword@99" });
      expect(postResetLogin.status).toBe(200);

      const dbCust = await User.findById(customerWithLegacyPw.id).lean();
      expect(dbCust?.password).toBe(legacyCustomerHash);
    });

    it("rolls back resetTokenConsumedAt if resetPassword fails inside the ACID transaction", async () => {
      const admin = await User.create({
        username: "Reset Rollback Admin",
        email: "reset.rollback@storra.test",
        phone: "9850000029",
        password: await bcrypt.hash("OldAdminPass@123", 10),
        role: "ADMIN",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      });

      const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);
      const forgotRes = await agent
        .post("/api/auth/forgot-password")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: admin.email });
      expect(forgotRes.status).toBe(200);

      const otp = await readOtpForChallenge(forgotRes.body.challengeId);
      const verifyResetRes = await agent
        .post("/api/auth/verify-reset-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({
          email: admin.email,
          otp,
          challengeId: forgotRes.body.challengeId,
        });
      expect(verifyResetRes.status).toBe(200);
      const resetCookieVal = parseSetCookies(verifyResetRes.headers["set-cookie"]).reset_token.value;

      // Force User.findByIdAndUpdate to return null inside tx -> 404 USER_NOT_FOUND & JTI rolled back
      const updateNullSpy = jest
        .spyOn(User, "findByIdAndUpdate")
        .mockResolvedValueOnce(null as unknown as ReturnType<typeof User.findByIdAndUpdate>);

      const failedReset = await request(appCtx.app)
        .post("/api/auth/reset-password")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .set("Cookie", [`csrfToken=${csrfToken}`, `reset_token=${resetCookieVal}`])
        .send({ newPassword: "RolledBackPassword@99" });
      expect(failedReset.status).toBe(404);
      expect(failedReset.body.code).toBe("USER_NOT_FOUND");
      updateNullSpy.mockRestore();

      const chgAfterRollback = await OtpChallenge.findOne({
        challengeId: forgotRes.body.challengeId,
      }).lean();
      expect(chgAfterRollback?.resetTokenConsumedAt).toBeNull();
      const unchangedAdmin = await User.findById(admin.id).lean();
      expect(unchangedAdmin?.tokenVersion).toBe(0);

      // Immediate retry with the SAME reset_token succeeds because resetTokenConsumedAt was rolled back!
      const retryReset = await request(appCtx.app)
        .post("/api/auth/reset-password")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .set("Cookie", [`csrfToken=${csrfToken}`, `reset_token=${resetCookieVal}`])
        .send({ newPassword: "RecoveredPassword@99" });
      expect(retryReset.status).toBe(200);
      const updatedAdmin = await User.findById(admin.id).lean();
      expect(updatedAdmin?.tokenVersion).toBe(1);
    });
  });

  describe("3. PR 1 & platform regression checks (SMS prep window, Razorpay webhook, notifications & orders)", () => {
    it("preserves existing MSG91 SMS customer signup/login, order notifications, and Razorpay raw-body HMAC webhook", async () => {
      jest.spyOn(globalThis, "fetch").mockImplementation(async (url, init) => {
        if (String(url).includes("/widget/verifyAccessToken")) {
          const payload = JSON.parse(String(init?.body ?? "{}")) as Record<string, string>;
          return {
            ok: true,
            status: 200,
            text: async () =>
              JSON.stringify({ type: "success", data: { mobile: payload["access-token"] } }),
          } as globalThis.Response;
        }
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ status: "success" }),
        } as globalThis.Response;
      });

      const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

      // 1. Existing SMS registration & login continue functioning alongside PR 2
      const regRes = await agent
        .post("/api/auth/mobile/register")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({
          name: "Prep SMS Customer",
          email: "prep.sms@storra.test",
          phone: "9860000111",
          accessToken: "919860000111",
        });
      expect(regRes.status).toBe(201);

      const smsLogin = await agent
        .post("/api/auth/mobile/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ phone: "9860000111", accessToken: "919860000111" });
      expect(smsLogin.status).toBe(200);

      // 2. POS order placement still creates Notification records cleanly
      const admin = await User.create({
        username: "Reg Admin",
        email: "reg.admin@storra.test",
        phone: "9860000112",
        role: "ADMIN",
        isActive: true,
        isVerified: true,
      });
      const cat = await Category.create({ code: "REG", name: "Reg Cat", isActive: true });
      const prod = await Product.create({
        code: "REG-1",
        name: "Reg Product",
        price: 250,
        stock: 5,
        isActive: true,
        categoryId: cat._id,
      });

      // Log in admin via real challenge flow
      await User.updateOne({ _id: admin._id }, { $set: { password: await bcrypt.hash("RegAdmin@123", 10) } });
      const adminS1 = await agent
        .post("/api/auth/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: admin.email, password: "RegAdmin@123" });
      const adminOtp = await readOtpForChallenge(adminS1.body.challengeId);
      const adminS2 = await agent
        .post("/api/auth/login/verify")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: admin.email, otp: adminOtp });
      const adminJwt = parseSetCookies(adminS2.headers["set-cookie"]).jwt.value;

      const orderRes = await request(appCtx.app)
        .post("/api/order/admin-order/place")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${adminJwt}`])
        .set("X-Forwarded-For", nextTestIp())
        .send({
          customerId: regRes.body.user.id,
          items: [{ productId: prod.id, quantity: 1 }],
          paymentMethod: "CASH",
        });
      expect(orderRes.status).toBe(201);
      expect(await Notification.countDocuments({ orderId: orderRes.body.order.id })).toBeGreaterThanOrEqual(1);

      // 3. Razorpay raw-body HMAC webhook remains exempted & verified
      const rawBody = '{"event":"payment.captured","payload":{"payment":{"entity":{"id":"pay_reg_1","order_id":"order_missing"}}}}';
      const sig = crypto
        .createHmac("sha256", env.RAZORPAY_WEBHOOK_SECRET || env.RAZORPAY_KEY_SECRET)
        .update(rawBody)
        .digest("hex");
      const whRes = await request(appCtx.app)
        .post("/api/order/razorpay-webhook")
        .set("Content-Type", "application/json")
        .set("x-razorpay-signature", sig)
        .send(rawBody);
      expect(whRes.status).toBe(200);
    });
  });
});

