import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import request from "supertest";
import { createApp } from "../src/server";
import { env } from "../src/config/env";
import { verifyMsg91Token } from "../src/controllers/auth.controller";
import { EmailOutbox, OtpChallenge, StaffProfile, User } from "../src/models/mongoose";
import { processOutboxBatchOnce } from "../src/services/emailOutbox.service";
import { decryptOutboxPayload } from "../src/utils/otpCrypto";
import {
  bootstrapCsrfAgent,
  nextTestIp,
  parseSetCookies,
} from "./helpers/httpHelper";
import { clearTestDb, startTestDb, stopTestDb } from "./helpers/testDb";

describe("PR 1 — Auth hardening, SMS binding, CSRF, webhook HMAC, & proxy config (#1-#4, #8-#12, #14)", () => {
  let appCtx: ReturnType<typeof createApp>;

  beforeAll(async () => {
    await startTestDb();
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

  // Test #1 & #2 & #11
  it("returns 410 Gone on legacy POST /api/auth/signup and POST /api/auth/mobile/check-phone, and issues no-store CSRF token on GET /api/auth/csrf", async () => {
    const { agent, ip, origin, csrfToken, cookies, res } = await bootstrapCsrfAgent(appCtx.app);

    expect(res.status).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(typeof csrfToken).toBe("string");
    expect(csrfToken.length).toBeGreaterThanOrEqual(32);
    expect(cookies.csrfToken?.value).toBe(csrfToken);

    const signupRes = await agent
      .post("/api/auth/signup")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", ip)
      .send({
        username: "Attacker",
        email: "attacker@storra.test",
        phone: "9812345678",
        password: "Password123!",
      });
    expect(signupRes.status).toBe(410);
    expect(signupRes.body.code).toBe("ENDPOINT_RETIRED");

    // Seed user to prove check-phone never leaks existence or role
    await User.create({
      username: "Target Admin",
      email: "target.admin@storra.test",
      phone: "9899887766",
      role: "ADMIN",
      isVerified: true,
      isActive: true,
    });

    const checkPhoneRes = await agent
      .post("/api/auth/mobile/check-phone")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", ip)
      .send({ phone: "9899887766" });
    expect(checkPhoneRes.status).toBe(410);
    expect(checkPhoneRes.body.code).toBe("ENDPOINT_RETIRED");
    expect(JSON.stringify(checkPhoneRes.body)).not.toMatch(/ADMIN/i);
  });

  // Test #3: verifyMsg91Token & mobileLogin & registerCustomer identifier binding
  describe("MSG91 token identifier binding (#3)", () => {
    it("verifyMsg91Token accepts canonical + prefix variants and fails closed when identifier is missing", async () => {
      for (const returnedId of ["9876543210", "919876543210", "+919876543210", "09876543210"]) {
        jest.spyOn(globalThis, "fetch").mockResolvedValueOnce({
          ok: true,
          status: 200,
          text: async () =>
            JSON.stringify({
              type: "success",
              data: { mobile: returnedId },
            }),
        } as globalThis.Response);

        const verified = await verifyMsg91Token("valid-msg91-token");
        expect(verified.ok).toBe(true);
        expect(verified.verifiedPhone).toBe("9876543210");
      }

      // Missing identifier even with type="success" -> fail closed
      jest.spyOn(globalThis, "fetch").mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ type: "success", message: "Verified without phone" }),
      } as globalThis.Response);

      const missingIdRes = await verifyMsg91Token("token-no-phone");
      expect(missingIdRes.ok).toBe(false);
      expect(missingIdRes.verifiedPhone).toBeNull();
    });

    it("allows mobileLogin when verified MSG91 mobile (+91 prefix) matches submitted phone, and rejects mismatch with 403", async () => {
      await User.create({
        username: "Customer One",
        email: "cust1@storra.test",
        phone: "9876543210",
        role: "CUSTOMER",
        isVerified: true,
        isActive: true,
      });

      jest.spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
        const payload = JSON.parse(String(init?.body ?? "{}")) as Record<string, string>;
        if (payload["access-token"] === "token-victim-A") {
          return {
            ok: true,
            status: 200,
            text: async () => JSON.stringify({ type: "success", mobile: "919876543210" }),
          } as globalThis.Response;
        }
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ type: "success", mobile: "919111111111" }),
        } as globalThis.Response;
      });

      const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

      // Mismatched token (verified 9111111111 submitted as 9876543210) -> 403
      const mismatchRes = await agent
        .post("/api/auth/mobile/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ phone: "9876543210", accessToken: "token-attacker-B" });
      expect(mismatchRes.status).toBe(403);
      expect(mismatchRes.body.code).toBe("PHONE_MISMATCH");

      // Matching token (+919876543210) -> 200 with session cookies
      const okRes = await agent
        .post("/api/auth/mobile/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ phone: "9876543210", accessToken: "token-victim-A" });
      expect(okRes.status).toBe(200);
      expect(okRes.body.user?.role).toBe("CUSTOMER");

      // Registration mismatch -> 403; matching registration -> 201
      const regMismatch = await agent
        .post("/api/auth/mobile/register")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({
          name: "New Customer",
          email: "new.cust@storra.test",
          phone: "9876500001",
          accessToken: "token-attacker-B",
        });
      expect(regMismatch.status).toBe(403);
      expect(regMismatch.body.code).toBe("PHONE_MISMATCH");
    });
  });

  // Test #4: Mobile login & registration role + active status guards
  it("rejects ADMIN, STAFF, SUPER_ADMIN, and inactive users from /api/auth/mobile/login and /api/auth/mobile/register (#4)", async () => {
    await User.insertMany([
      {
        username: "Admin User",
        email: "admin@storra.test",
        phone: "9800000010",
        role: "ADMIN",
        isActive: true,
        isVerified: true,
      },
      {
        username: "Staff User",
        email: "staff@storra.test",
        phone: "9800000011",
        role: "STAFF",
        isActive: true,
        isVerified: true,
      },
      {
        username: "Super User",
        email: "super@storra.test",
        phone: "9800000012",
        role: "SUPER_ADMIN",
        isActive: true,
        isVerified: true,
      },
      {
        username: "Disabled Customer",
        email: "disabled.cust@storra.test",
        phone: "9800000013",
        role: "CUSTOMER",
        isActive: false,
        isVerified: true,
      },
    ]);

    jest.spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
      const payload = JSON.parse(String(init?.body ?? "{}")) as Record<string, string>;
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ type: "success", mobile: payload["access-token"] }),
      } as globalThis.Response;
    });

    const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

    for (const phone of ["9800000010", "9800000011", "9800000012"]) {
      const res = await agent
        .post("/api/auth/mobile/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ phone, accessToken: `91${phone}` });
      expect(res.status).toBe(403);
      expect(res.body.code).toBe("ROLE_RESTRICTED");
    }

    const inactiveRes = await agent
      .post("/api/auth/mobile/login")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ phone: "9800000013", accessToken: "919800000013" });
    expect(inactiveRes.status).toBe(403);
    expect(inactiveRes.body.code).toBe("ACCOUNT_DEACTIVATED");

    // Attempting /api/auth/mobile/register against an existing ADMIN email or phone fails with 409 DUPLICATE
    const regCollision = await agent
      .post("/api/auth/mobile/register")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        name: "Impersonator",
        email: "admin@storra.test",
        phone: "9800000099",
        accessToken: "919800000099",
      });
    expect(regCollision.status).toBe(409);
    expect(regCollision.body.code).toBe("DUPLICATE");
  });

  // Test #8 & #9: Password login + password reset separation & cookie flags
  it("blocks CUSTOMER & inactive users from password login/OTP/reset endpoints, and hardens reset_token cookie flags (#8, #9)", async () => {
    const pwHash = await bcrypt.hash("StrongPass@123", 10);

    await User.create({
      username: "Legacy Pw Customer",
      email: "cust.pw@storra.test",
      phone: "9810000001",
      password: pwHash,
      role: "CUSTOMER",
      isActive: true,
      isVerified: true,
    });

    const inactiveStaffUser = await User.create({
      username: "Inactive Staff",
      email: "staff.off@storra.test",
      phone: "9810000002",
      password: pwHash,
      role: "STAFF",
      isActive: true,
      isVerified: true,
    });
    await StaffProfile.create({
      userId: inactiveStaffUser._id,
      managedBy: inactiveStaffUser._id,
      permissions: [],
      isActive: false,
    });

    await User.create({
      username: "Disabled Admin",
      email: "admin.off@storra.test",
      phone: "9810000003",
      password: pwHash,
      role: "ADMIN",
      isActive: false,
      isVerified: true,
    });

    await User.create({
      username: "Active Admin",
      email: "admin.on@storra.test",
      phone: "9810000004",
      password: pwHash,
      role: "ADMIN",
      isActive: true,
      isVerified: true,
    });

    jest.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ status: "success" }),
    } as globalThis.Response);

    const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

    // 1. CUSTOMER blocked from password login & password reset via non-enumerating decoy
    const custLogin = await agent
      .post("/api/auth/login")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: "cust.pw@storra.test", password: "StrongPass@123" });
    expect(custLogin.status).toBe(403);
    expect(custLogin.body.code).toBe("ROLE_RESTRICTED");

    const fetchSpy = jest.spyOn(globalThis, "fetch");
    const custForgot = await agent
      .post("/api/auth/forgot-password")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: "cust.pw@storra.test" });
    expect(custForgot.status).toBe(200);
    expect(custForgot.body.message).toMatch(/If an eligible account exists/i);
    expect(custForgot.body.challengeId).toBeTruthy();

    const decoyChallenge = await OtpChallenge.findOne({
      challengeId: custForgot.body.challengeId,
    }).lean();
    expect(decoyChallenge?.isDecoy).toBe(true);
    expect(decoyChallenge?.deliveryStatus).toBe("suppressed");
    await processOutboxBatchOnce();
    expect(fetchSpy).not.toHaveBeenCalled();

    const custResetOtpAttempt = await agent
      .post("/api/auth/verify-reset-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        email: "cust.pw@storra.test",
        challengeId: custForgot.body.challengeId,
        otp: "123456",
      });
    expect(custResetOtpAttempt.status).toBe(401);

    // 2. Customer or cold caller hitting login/verify without admin_login_challenge cookie -> 401 CHALLENGE_MISSING
    const custVerify = await agent
      .post("/api/auth/login/verify")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: "cust.pw@storra.test", otp: "123456" });
    expect(custVerify.status).toBe(401);
    expect(custVerify.body.code).toBe("CHALLENGE_MISSING");

    // 3. Inactive STAFF (StaffProfile.isActive: false) & inactive ADMIN blocked
    const staffOffLogin = await agent
      .post("/api/auth/login")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: "staff.off@storra.test", password: "StrongPass@123" });
    expect(staffOffLogin.status).toBe(403);

    const adminOffLogin = await agent
      .post("/api/auth/login")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: "admin.off@storra.test", password: "StrongPass@123" });
    expect(adminOffLogin.status).toBe(403);

    // 4. Forged reset_token rejected (missing jti -> 401 RESET_TOKEN_INVALID; with jti for CUSTOMER -> 403 ROLE_RESTRICTED)
    const missingJtiResetToken = jwt.sign(
      { email: "cust.pw@storra.test", purpose: "password_reset" },
      env.JWT_SECRET,
      { expiresIn: "10m" },
    );
    const missingJtiRes = await request(appCtx.app)
      .post("/api/auth/reset-password")
      .set("Origin", origin)
      .set("Cookie", [`csrfToken=${csrfToken}`, `reset_token=${missingJtiResetToken}`])
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ newPassword: "NewPassword@123" });
    expect(missingJtiRes.status).toBe(401);
    expect(missingJtiRes.body.code).toBe("RESET_TOKEN_INVALID");

    const custResetToken = jwt.sign(
      { email: "cust.pw@storra.test", purpose: "password_reset", jti: "forged-jti-1" },
      env.JWT_SECRET,
      { expiresIn: "10m" },
    );
    const custResetRes = await request(appCtx.app)
      .post("/api/auth/reset-password")
      .set("Origin", origin)
      .set("Cookie", [`csrfToken=${csrfToken}`, `reset_token=${custResetToken}`])
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ newPassword: "NewPassword@123" });
    expect(custResetRes.status).toBe(403);
    expect(custResetRes.body.code).toBe("ROLE_RESTRICTED");

    // 5. Active ADMIN password-first login -> admin_login_challenge cookie -> verifyLoginOtp via EmailOutbox succeeds;
    // cold resendOtp without pre-auth challenge cookie rejected with 401 CHALLENGE_MISSING
    const custResend = await agent
      .post("/api/auth/resend-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: "cust.pw@storra.test" });
    expect(custResend.status).toBe(401);
    expect(custResend.body.code).toBe("CHALLENGE_MISSING");

    const adminLoginRes = await agent
      .post("/api/auth/login")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: "admin.on@storra.test", password: "StrongPass@123" });
    expect(adminLoginRes.status).toBe(200);
    expect(adminLoginRes.body.step).toBe("VERIFY_OTP");
    expect(adminLoginRes.body.challengeId).toBeTruthy();

    const loginChallengeCookies = parseSetCookies(adminLoginRes.headers["set-cookie"]);
    expect(loginChallengeCookies.admin_login_challenge?.value).toBeTruthy();
    expect(loginChallengeCookies.admin_login_challenge?.httpOnly).toBe(true);

    const loginChallengeDoc = await OtpChallenge.findOne({
      challengeId: adminLoginRes.body.challengeId,
      purpose: "admin_login",
    }).lean();
    expect(loginChallengeDoc?.otpHash).toMatch(/^[a-f0-9]{64}$/);
    expect((loginChallengeDoc as unknown as Record<string, unknown>)?.otp).toBeUndefined();

    const loginOutbox = await EmailOutbox.findOne({
      challengeId: adminLoginRes.body.challengeId,
    }).lean();
    expect(loginOutbox?.encryptedPayload).toBeTruthy();
    const decryptedLoginOtp = decryptOutboxPayload(loginOutbox!.encryptedPayload!).variables.OTP;
    expect(decryptedLoginOtp).toMatch(/^\d{6}$/);

    await processOutboxBatchOnce();
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    const verifyLoginRes = await agent
      .post("/api/auth/login/verify")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        email: "admin.on@storra.test",
        otp: decryptedLoginOtp,
        challengeId: adminLoginRes.body.challengeId,
      });
    expect(verifyLoginRes.status).toBe(200);
    expect(verifyLoginRes.body.role).toBe("ADMIN");

    const loginCookies = parseSetCookies(verifyLoginRes.headers["set-cookie"]);
    expect(loginCookies.jwt?.value).toBeTruthy();
    expect(loginCookies.refreshToken?.value).toBeTruthy();
    expect(loginCookies.admin_login_challenge?.value).toBe("");
    const decodedLoginJwt = jwt.verify(loginCookies.jwt.value, env.JWT_SECRET) as {
      tokenVersion?: number;
    };
    expect(decodedLoginJwt.tokenVersion).toBe(0);

    // 6. Active ADMIN forgotPassword -> verifyResetOtp sets httpOnly + sameSite reset_token with single-use jti
    const forgotResetRes = await agent
      .post("/api/auth/forgot-password")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: "admin.on@storra.test" });
    expect(forgotResetRes.status).toBe(200);
    expect(forgotResetRes.body.challengeId).toBeTruthy();

    const resetOutbox = await EmailOutbox.findOne({
      challengeId: forgotResetRes.body.challengeId,
    }).lean();
    const decryptedResetOtp = decryptOutboxPayload(resetOutbox!.encryptedPayload!).variables.OTP;

    const verifyResetRes = await agent
      .post("/api/auth/verify-reset-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        email: "admin.on@storra.test",
        otp: decryptedResetOtp,
        challengeId: forgotResetRes.body.challengeId,
      });
    expect(verifyResetRes.status).toBe(200);

    const cookies = parseSetCookies(verifyResetRes.headers["set-cookie"]);
    expect(cookies.reset_token).toBeDefined();
    expect(cookies.reset_token.httpOnly).toBe(true);
    expect(cookies.reset_token.sameSite?.toLowerCase()).toBe("lax");
    expect(cookies.reset_token.path).toBe("/");

    const decodedResetToken = jwt.verify(cookies.reset_token.value, env.JWT_SECRET) as {
      jti?: string;
    };
    expect(decodedResetToken.jti).toBeTruthy();
    const consumedResetChallenge = await OtpChallenge.findOne({
      challengeId: forgotResetRes.body.challengeId,
    }).lean();
    expect(consumedResetChallenge?.resetTokenJti).toBe(decodedResetToken.jti);
  });

  // Test #10: CSRF enforcement on unauthenticated & authenticated mutations
  describe("CSRF double-submit + Origin/Referer hardening (#10)", () => {
    it("rejects unauthenticated mutating calls with missing origin, disallowed origin, null origin, missing cookie, missing header, wrong-length header, or mismatched header", async () => {
      const { csrfToken } = await bootstrapCsrfAgent(appCtx.app);
      const validBody = {
        customerName: "Guest",
        paymentMethod: "ONLINE",
        triggerSource: "CHECKOUT_CANCELLED",
        selectedReasons: ["Shipping charge too high"],
      };

      // Missing Origin / Referer -> 403
      const noOrigin = await request(appCtx.app)
        .post("/api/purchase-feedback")
        .set("Cookie", [`csrfToken=${csrfToken}`])
        .set("X-CSRF-Token", csrfToken)
        .send(validBody);
      expect(noOrigin.status).toBe(403);
      expect(noOrigin.body.code).toBe("CSRF_ORIGIN_INVALID");

      // Disallowed Origin -> 403
      const badOrigin = await request(appCtx.app)
        .post("/api/purchase-feedback")
        .set("Origin", "https://evil.attacker.example")
        .set("Cookie", [`csrfToken=${csrfToken}`])
        .set("X-CSRF-Token", csrfToken)
        .send(validBody);
      expect(badOrigin.status).toBe(403);
      expect(badOrigin.body.code).toBe("CSRF_ORIGIN_INVALID");

      // Origin: null -> 403
      const nullOrigin = await request(appCtx.app)
        .post("/api/purchase-feedback")
        .set("Origin", "null")
        .set("Cookie", [`csrfToken=${csrfToken}`])
        .set("X-CSRF-Token", csrfToken)
        .send(validBody);
      expect(nullOrigin.status).toBe(403);
      expect(nullOrigin.body.code).toBe("CSRF_ORIGIN_INVALID");

      // Missing csrfToken cookie -> 403
      const noCookie = await request(appCtx.app)
        .post("/api/purchase-feedback")
        .set("Origin", "http://localhost:5173")
        .set("X-CSRF-Token", csrfToken)
        .send(validBody);
      expect(noCookie.status).toBe(403);
      expect(noCookie.body.code).toBe("CSRF_INVALID");

      // Missing X-CSRF-Token header -> 403
      const noHeader = await request(appCtx.app)
        .post("/api/purchase-feedback")
        .set("Origin", "http://localhost:5173")
        .set("Cookie", [`csrfToken=${csrfToken}`])
        .send(validBody);
      expect(noHeader.status).toBe(403);
      expect(noHeader.body.code).toBe("CSRF_INVALID");

      // Wrong-length X-CSRF-Token -> 403 without timingSafeEqual RangeError
      const shortHeader = await request(appCtx.app)
        .post("/api/purchase-feedback")
        .set("Origin", "http://localhost:5173")
        .set("Cookie", [`csrfToken=${csrfToken}`])
        .set("X-CSRF-Token", "short")
        .send(validBody);
      expect(shortHeader.status).toBe(403);
      expect(shortHeader.body.code).toBe("CSRF_INVALID");

      // Mismatched same-length X-CSRF-Token -> 403
      const wrongSameLength =
        (csrfToken[0] === "a" ? "b" : "a") + csrfToken.slice(1);
      const mismatchRes = await request(appCtx.app)
        .post("/api/purchase-feedback")
        .set("Origin", "http://localhost:5173")
        .set("Cookie", [`csrfToken=${csrfToken}`])
        .set("X-CSRF-Token", wrongSameLength)
        .send(validBody);
      expect(mismatchRes.status).toBe(403);
      expect(mismatchRes.body.code).toBe("CSRF_INVALID");

      // Valid bootstrapped cookie + matching X-CSRF-Token + allowed Origin -> 201!
      const okRes = await request(appCtx.app)
        .post("/api/purchase-feedback")
        .set("Origin", "http://localhost:5173")
        .set("Cookie", [`csrfToken=${csrfToken}`])
        .set("X-CSRF-Token", csrfToken)
        .send(validBody);
      expect(okRes.status).toBe(201);
    });
  });

  // Test #12 & #14: Razorpay webhook exemption + exact raw-body HMAC + trust proxy config
  it("verifies POST /api/order/razorpay-webhook without CSRF/Origin using exact raw bytes, and configures TRUST_PROXY_HOPS (#12, #14)", async () => {
    expect(appCtx.app.get("trust proxy")).toBe(1);

    const rawBody = '{"event":"payment.captured","payload":{"payment":{"entity":{"id":"pay_1","order_id":"order_missing_1"}}}}';
    const webhookSecret = env.RAZORPAY_WEBHOOK_SECRET || env.RAZORPAY_KEY_SECRET;
    const validSig = crypto
      .createHmac("sha256", webhookSecret)
      .update(rawBody)
      .digest("hex");

    // 1. Valid raw wire body & signature, NO Origin/CSRF headers -> 200
    const okRes = await request(appCtx.app)
      .post("/api/order/razorpay-webhook")
      .set("Content-Type", "application/json")
      .set("x-razorpay-signature", validSig)
      .send(rawBody);
    expect(okRes.status).toBe(200);

    // 2. Identical JSON semantics with 1 extra space before '}' but original signature -> 400 invalid signature (proves raw wire bytes used, not JSON.stringify)
    const tamperedRawBody = `${rawBody.slice(0, -1)} }`;
    const tamperedRes = await request(appCtx.app)
      .post("/api/order/razorpay-webhook")
      .set("Content-Type", "application/json")
      .set("x-razorpay-signature", validSig)
      .send(tamperedRawBody);
    expect(tamperedRes.status).toBe(400);

    // 3. Invalid signature length -> 400
    const badLenRes = await request(appCtx.app)
      .post("/api/order/razorpay-webhook")
      .set("Content-Type", "application/json")
      .set("x-razorpay-signature", "badlen")
      .send(rawBody);
    expect(badLenRes.status).toBe(400);
  });
});
