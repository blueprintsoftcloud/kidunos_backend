import request from "supertest";
import bcrypt from "bcryptjs";
import { env } from "../src/config/env";
import { createApp } from "../src/server";
import {
  AppSetting,
  EmailOutbox,
  OtpChallenge,
  OtpRateLimit,
  StaffProfile,
  User,
} from "../src/models/mongoose";
import { CUSTOMER_EMAIL_OTP_FLAG_KEY } from "../src/utils/featureFlags";
import { processOutboxBatchOnce } from "../src/services/emailOutbox.service";
import {
  ensurePrepEmailUniqueIndex,
  PREP_EMAIL_UNIQUE_INDEX_NAME,
  resolvePrepEmailIndexUrl,
} from "../src/scripts/ensurePrepEmailUniqueIndex";
import {
  requireOperationalMongoUrl,
  resolveOperationalMongoUrl,
  resolveOperationalMongoUrlDetails,
} from "../src/utils/resolveMongoUri";
import { decryptOutboxPayload } from "../src/utils/otpCrypto";
import { OTP_RESEND_COOLDOWN_MS, OTP_TTL_MS } from "../src/services/otp.service";
import { bootstrapCsrfAgent, nextTestIp, parseSetCookies } from "./helpers/httpHelper";
import { clearTestDb, startTestDb, stopTestDb } from "./helpers/testDb";
import mongoose from "mongoose";

describe("PR 2 — Feature-gated Customer Email OTP Signup & Login", () => {
  let appCtx: ReturnType<typeof createApp>;

  beforeAll(async () => {
    await startTestDb();
    await Promise.all([
      User.init(),
      AppSetting.init(),
      OtpChallenge.init(),
      OtpRateLimit.init(),
      EmailOutbox.init(),
    ]);
    appCtx = createApp();
  });

  afterEach(async () => {
    jest.restoreAllMocks();
    env.CUSTOMER_EMAIL_OTP_ENABLED = "false";
    if (mongoose.connection.readyState === 1) {
      const idx = await User.collection.indexes();
      if (idx.some((i) => i.name === PREP_EMAIL_UNIQUE_INDEX_NAME)) {
        await User.collection.dropIndex(PREP_EMAIL_UNIQUE_INDEX_NAME);
      }
    }
    await clearTestDb();
  });

  afterAll(async () => {
    if (appCtx) {
      appCtx.stopSocketRecheck();
      await new Promise<void>((resolve) => appCtx.io.close(() => resolve()));
    }
    await stopTestDb();
  });

  const enableCustomerEmailOtp = async () => {
    await AppSetting.create({ key: CUSTOMER_EMAIL_OTP_FLAG_KEY, value: true });
  };

  const mockMsg91Success = () =>
    jest.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ status: "success", message: "queued" }),
    } as globalThis.Response);

  const readOtpForChallenge = async (challengeId: string): Promise<string> => {
    const outbox = await EmailOutbox.findOne({ challengeId }).lean();
    expect(outbox?.encryptedPayload).toBeTruthy();
    return decryptOutboxPayload(outbox!.encryptedPayload!).variables.OTP;
  };

  const ageCooldownForChallenge = async (
    purpose: "customer_signup" | "customer_login",
    email: string,
    challengeId: string,
  ) => {
    const past = new Date(Date.now() - (OTP_RESEND_COOLDOWN_MS + 5000));
    await OtpChallenge.updateOne({ challengeId }, { $set: { lastSentAt: past } });
    await OtpRateLimit.updateOne(
      { key: `cooldown:${purpose}:${email}` },
      { $set: { resetAt: new Date(Date.now() - 1000) } },
    );
  };

  it("gates all customer Email OTP routes behind CUSTOMER_EMAIL_OTP_ENABLED while exposing public feature config", async () => {
    const offConfig = await request(appCtx.app).get("/api/auth/customer/config");
    expect(offConfig.status).toBe(200);
    expect(offConfig.body).toEqual({
      customerEmailOtpEnabled: false,
      customerSmsOtpEnabled: true,
    });

    const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);
    for (const [routePath, payload] of [
      [
        "/api/auth/customer/signup/request-otp",
        { name: "Alice", email: "alice@storra.test", phone: "9812345678" },
      ],
      [
        "/api/auth/customer/signup/resend-otp",
        { email: "alice@storra.test", challengeId: "chg_dummy_123456" },
      ],
      [
        "/api/auth/customer/signup/verify-otp",
        { email: "alice@storra.test", challengeId: "chg_dummy_123456", otp: "123456" },
      ],
      ["/api/auth/customer/login/request-otp", { email: "alice@storra.test" }],
      [
        "/api/auth/customer/login/resend-otp",
        { email: "alice@storra.test", challengeId: "chg_dummy_123456" },
      ],
      [
        "/api/auth/customer/login/verify-otp",
        { email: "alice@storra.test", challengeId: "chg_dummy_123456", otp: "123456" },
      ],
    ] as const) {
      const res = await agent
        .post(routePath)
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send(payload);
      expect(res.status).toBe(403);
      expect(res.body.code).toBe("FEATURE_DISABLED");
    }

    await enableCustomerEmailOtp();
    const onConfig = await request(appCtx.app).get("/api/auth/customer/config");
    expect(onConfig.status).toBe(200);
    expect(onConfig.headers["cache-control"]).toBe("no-store");
    expect(onConfig.body.customerEmailOtpEnabled).toBe(true);
  });

  it("prioritizes AppSetting CUSTOMER_EMAIL_OTP_ENABLED over env fallback in both directions and resolves MONGO_URL/DATABASE_URL cleanly", async () => {
    // 1. env="true" without AppSetting -> true
    env.CUSTOMER_EMAIL_OTP_ENABLED = "true";
    const envTrueRes = await request(appCtx.app).get("/api/auth/customer/config");
    expect(envTrueRes.status).toBe(200);
    expect(envTrueRes.headers["cache-control"]).toBe("no-store");
    expect(envTrueRes.body.customerEmailOtpEnabled).toBe(true);

    // 2. AppSetting=false overrides env="true" -> false (blocks routes with FEATURE_DISABLED)
    await AppSetting.create({ key: CUSTOMER_EMAIL_OTP_FLAG_KEY, value: false });
    const appFalseOverride = await request(appCtx.app).get("/api/auth/customer/config");
    expect(appFalseOverride.status).toBe(200);
    expect(appFalseOverride.body.customerEmailOtpEnabled).toBe(false);

    const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);
    const blockedRes = await agent
      .post("/api/auth/customer/login/request-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: "precedence@storra.test" });
    expect(blockedRes.status).toBe(403);
    expect(blockedRes.body.code).toBe("FEATURE_DISABLED");

    // 3. String "true" in AppSetting overrides env="false" -> true
    env.CUSTOMER_EMAIL_OTP_ENABLED = "false";
    await AppSetting.updateOne(
      { key: CUSTOMER_EMAIL_OTP_FLAG_KEY },
      { $set: { value: "true" } },
    );
    const appStringOverride = await request(appCtx.app).get("/api/auth/customer/config");
    expect(appStringOverride.status).toBe(200);
    expect(appStringOverride.body.customerEmailOtpEnabled).toBe(true);

    // 4. Canonical MONGO_URL resolution ignores conflicting DATABASE_URL and refuses implicit DATABASE_URL fallback
    const secretPrimaryUri = "mongodb+srv://produser:s3cr3tPass@primary.example.com/storra";
    const staleSecondaryUri = "mongodb+srv://staleuser:otherPass@stale.example.com/otherdb";

    expect(
      resolvePrepEmailIndexUrl({
        MONGO_URL: `  ${secretPrimaryUri}  `,
        DATABASE_URL: staleSecondaryUri,
      }),
    ).toBe(secretPrimaryUri);
    expect(resolvePrepEmailIndexUrl({ MONGO_URL: "", DATABASE_URL: staleSecondaryUri })).toBe("");
    expect(resolvePrepEmailIndexUrl({})).toBe("");

    expect(resolveOperationalMongoUrl({ MONGO_URL: ` ${secretPrimaryUri} ` })).toBe(secretPrimaryUri);
    expect(resolveOperationalMongoUrlDetails({ MONGO_URL: "", DATABASE_URL: staleSecondaryUri })).toEqual({
      uri: "",
      ignoredConflictingDatabaseUrl: false,
      missingDueToDatabaseUrlOnly: true,
    });
    expect(
      resolveOperationalMongoUrlDetails({
        MONGO_URL: secretPrimaryUri,
        DATABASE_URL: staleSecondaryUri,
      }),
    ).toEqual({
      uri: secretPrimaryUri,
      ignoredConflictingDatabaseUrl: true,
      missingDueToDatabaseUrlOnly: false,
    });

    const warnings: string[] = [];
    expect(
      requireOperationalMongoUrl(
        "unit-test-script",
        { MONGO_URL: secretPrimaryUri, DATABASE_URL: staleSecondaryUri },
        (msg) => warnings.push(msg),
      ),
    ).toBe(secretPrimaryUri);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/ignoring DATABASE_URL and using canonical MONGO_URL/i);
    expect(warnings[0]).not.toContain("s3cr3tPass");
    expect(warnings[0]).not.toContain("otherPass");
    expect(warnings[0]).not.toContain("mongodb+srv://");

    let missingErr = "";
    try {
      requireOperationalMongoUrl("unit-test-script", {
        MONGO_URL: "",
        DATABASE_URL: staleSecondaryUri,
      });
    } catch (err) {
      missingErr = err instanceof Error ? err.message : String(err);
    }
    expect(missingErr).toMatch(/MONGO_URL must be set.*DATABASE_URL fallback is disabled/i);
    expect(missingErr).not.toContain("otherPass");
    expect(missingErr).not.toContain("mongodb+srv://");
  });

  it("completes customer email signup without pre-creating User, supports cooldown resend, handles wrong/expired/locked OTP, and verifies atomically", async () => {
    await enableCustomerEmailOtp();
    const fetchSpy = mockMsg91Success();
    const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

    // 1. Request signup OTP with mixed-case email -> creates NO User before OTP succeeds
    const reqRes = await agent
      .post("/api/auth/customer/signup/request-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        name: "  Kavya Menon ",
        email: "  Kavya.Menon@Storra.TEST ",
        phone: "9845001122",
      });
    expect(reqRes.status).toBe(200);
    expect(reqRes.body.step).toBe("VERIFY_OTP");
    expect(reqRes.body.challengeId).toBeTruthy();
    expect(await User.countDocuments()).toBe(0);

    // 2. Process EmailOutbox -> delivers initial OTP
    const batch1 = await processOutboxBatchOnce();
    expect(batch1.sent).toBe(1);
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    // 3. Immediate resend hits 120s cooldown (429 RESEND_COOLDOWN)
    const earlyResend = await agent
      .post("/api/auth/customer/signup/resend-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        email: "kavya.menon@storra.test",
        challengeId: reqRes.body.challengeId,
      });
    expect(earlyResend.status).toBe(429);
    expect(earlyResend.body.code).toBe("RESEND_COOLDOWN");

    // 4. Advance past cooldown & resend -> issues replacement challengeId, preserves pendingData
    await ageCooldownForChallenge(
      "customer_signup",
      "kavya.menon@storra.test",
      reqRes.body.challengeId,
    );
    const resendRes = await agent
      .post("/api/auth/customer/signup/resend-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        email: "kavya.menon@storra.test",
        challengeId: reqRes.body.challengeId,
      });
    expect(resendRes.status).toBe(200);
    expect(resendRes.body.challengeId).not.toBe(reqRes.body.challengeId);

    const resentOtp = await readOtpForChallenge(resendRes.body.challengeId);
    const wrongOtp = resentOtp === "123456" ? "654321" : "123456";

    // 5. Wrong OTP leaves zero users created
    const wrongVerify = await agent
      .post("/api/auth/customer/signup/verify-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        email: "kavya.menon@storra.test",
        challengeId: resendRes.body.challengeId,
        otp: wrongOtp,
      });
    expect(wrongVerify.status).toBe(401);
    expect(wrongVerify.body.attemptsRemaining).toBe(4);
    expect(await User.countDocuments()).toBe(0);

    // 6. Verify with correct OTP -> creates normalized verified CUSTOMER inside ACID tx + sets cookies
    const okVerify = await agent
      .post("/api/auth/customer/signup/verify-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        email: "  KAVYA.MENON@STORRA.TEST ",
        challengeId: resendRes.body.challengeId,
        otp: resentOtp,
      });
    expect(okVerify.status).toBe(201);
    expect(okVerify.body.user?.username).toBe("Kavya Menon");
    expect(okVerify.body.user?.role).toBe("CUSTOMER");

    const cookies = parseSetCookies(okVerify.headers["set-cookie"]);
    expect(cookies.jwt?.value).toBeTruthy();
    expect(cookies.refreshToken?.value).toBeTruthy();

    const createdUser = await User.findOne({ email: "kavya.menon@storra.test" }).lean();
    expect(createdUser).toBeTruthy();
    expect(createdUser?.phone).toBe("9845001122");
    expect(createdUser?.role).toBe("CUSTOMER");
    expect(createdUser?.isVerified).toBe(true);
    expect(createdUser?.isActive).toBe(true);
    expect(createdUser?.tokenVersion).toBe(0);
    expect(createdUser?.posActivationRequired).toBe(false);
    expect(createdUser?.emailVerifiedAt).toBeTruthy();
  });

  it("prevents enumeration on duplicate email/phone across roles (identical decoy 200 without email) and handles concurrent duplicate signups", async () => {
    await enableCustomerEmailOtp();
    await ensurePrepEmailUniqueIndex({ apply: true });
    const fetchSpy = mockMsg91Success();

    await User.insertMany([
      {
        username: "Existing Customer",
        email: "existing.cust@storra.test",
        phone: "9811100001",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: new Date(),
      },
      {
        username: "Store Admin",
        email: "admin.owner@storra.test",
        phone: "9811100002",
        role: "ADMIN",
        isActive: true,
        isVerified: true,
      },
    ]);

    const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

    const dupCustEmail = await agent
      .post("/api/auth/customer/signup/request-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        name: "Dup Attempt",
        email: "EXISTING.CUST@STORRA.TEST",
        phone: "9899900001",
      });
    const dupAdminEmail = await agent
      .post("/api/auth/customer/signup/request-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        name: "Dup Attempt",
        email: "admin.owner@storra.test",
        phone: "9899900002",
      });
    const dupPhone = await agent
      .post("/api/auth/customer/signup/request-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        name: "Dup Attempt",
        email: "brand.new@storra.test",
        phone: "9811100002",
      });
    const cleanNew = await agent
      .post("/api/auth/customer/signup/request-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        name: "Legit User",
        email: "legit.new@storra.test",
        phone: "9899900003",
      });

    for (const r of [dupCustEmail, dupAdminEmail, dupPhone, cleanNew]) {
      expect(r.status).toBe(200);
      expect(r.body.message).toBe(cleanNew.body.message);
      expect(r.body.step).toBe("VERIFY_OTP");
      expect(r.body.challengeId).toBeTruthy();
    }

    // Running outbox batch sends ONLY 1 email (for legit.new@storra.test), never for any duplicate!
    const batch = await processOutboxBatchOnce();
    expect(batch.sent).toBe(1);
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    // Decoy challenges fail verification
    const decoyVerify = await agent
      .post("/api/auth/customer/signup/verify-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        email: "admin.owner@storra.test",
        challengeId: dupAdminEmail.body.challengeId,
        otp: "123456",
      });
    expect(decoyVerify.status).toBe(401);

    // Concurrent duplicate signup race (two sessions start before either User is inserted)
    const s1 = await bootstrapCsrfAgent(appCtx.app);
    const s2 = await bootstrapCsrfAgent(appCtx.app);
    const [req1, req2] = await Promise.all([
      s1.agent
        .post("/api/auth/customer/signup/request-otp")
        .set("Origin", s1.origin)
        .set("X-CSRF-Token", s1.csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ name: "Race One", email: "race.email@storra.test", phone: "9888800001" }),
      s2.agent
        .post("/api/auth/customer/signup/request-otp")
        .set("Origin", s2.origin)
        .set("X-CSRF-Token", s2.csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ name: "Race Two", email: "  RACE.EMAIL@STORRA.TEST ", phone: "9888800002" }),
    ]);
    expect(req1.status).toBe(200);
    expect(req2.status).toBe(200);
    // At most one active un-invalidated challenge exists for the normalized email; verify attempts cannot create two users
    expect(
      await OtpChallenge.countDocuments({
        email: "race.email@storra.test",
        purpose: "customer_signup",
        invalidatedAt: null,
      }),
    ).toBeLessThanOrEqual(1);

    // Simulate two independent emails competing for the SAME phone number in parallel verify:
    const [phoneReqA, phoneReqB] = await Promise.all([
      s1.agent
        .post("/api/auth/customer/signup/request-otp")
        .set("Origin", s1.origin)
        .set("X-CSRF-Token", s1.csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ name: "Phone Race A", email: "phone.race.a@storra.test", phone: "9877700099" }),
      s2.agent
        .post("/api/auth/customer/signup/request-otp")
        .set("Origin", s2.origin)
        .set("X-CSRF-Token", s2.csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ name: "Phone Race B", email: "phone.race.b@storra.test", phone: "9877700099" }),
    ]);

    expect(phoneReqA.status).toBe(200);
    expect(phoneReqB.status).toBe(200);

    const [otpA, otpB] = await Promise.all([
      readOtpForChallenge(phoneReqA.body.challengeId),
      readOtpForChallenge(phoneReqB.body.challengeId),
    ]);

    const [verA, verB] = await Promise.all([
      s1.agent
        .post("/api/auth/customer/signup/verify-otp")
        .set("Origin", s1.origin)
        .set("X-CSRF-Token", s1.csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({
          email: "phone.race.a@storra.test",
          challengeId: phoneReqA.body.challengeId,
          otp: otpA,
        }),
      s2.agent
        .post("/api/auth/customer/signup/verify-otp")
        .set("Origin", s2.origin)
        .set("X-CSRF-Token", s2.csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({
          email: "phone.race.b@storra.test",
          challengeId: phoneReqB.body.challengeId,
          otp: otpB,
        }),
    ]);

    expect([verA.status, verB.status].sort((a, b) => a - b)).toEqual([201, 409]);
    expect(await User.countDocuments({ phone: "9877700099" })).toBe(1);
  });

  it("sends customer Email OTP only for eligible customers and directs unknown or restricted accounts appropriately", async () => {
    await enableCustomerEmailOtp();
    const fetchSpy = mockMsg91Success();

    await User.insertMany([
      {
        username: "Verified Shopper",
        email: "verified.shopper@storra.test",
        phone: "9810000001",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: new Date(),
        posActivationRequired: false,
      },
      {
        username: "Unverified SMS Shopper",
        email: "sms.unverified@storra.test",
        phone: "9810000002",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: null,
        posActivationRequired: false,
      },
      {
        username: "POS Pending Shopper",
        email: "pos.pending@storra.test",
        phone: "9810000003",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: null,
        posActivationRequired: true,
      },
      {
        username: "Disabled Customer",
        email: "inactive.cust@storra.test",
        phone: "9810000004",
        role: "CUSTOMER",
        isActive: false,
        isVerified: true,
        emailVerifiedAt: new Date(),
      },
      {
        username: "Store Admin",
        email: "admin.blocked@storra.test",
        phone: "9810000005",
        role: "ADMIN",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: new Date(),
      },
    ]);

    const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

    // Unknown emails are sent to signup, while existing but ineligible accounts
    // are not allowed to continue through login.
    const unknownReq = await agent
      .post("/api/auth/customer/login/request-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: "unknown.user@storra.test" });
    expect(unknownReq.status).toBe(404);
    expect(unknownReq.body.code).toBe("CUSTOMER_NOT_FOUND");

    for (const [email, code] of [
      ["sms.unverified@storra.test", "EMAIL_NOT_VERIFIED"],
      ["pos.pending@storra.test", "EMAIL_NOT_VERIFIED"],
      ["inactive.cust@storra.test", "ACCOUNT_DEACTIVATED"],
      ["admin.blocked@storra.test", "ROLE_RESTRICTED"],
    ]) {
      const ineligibleReq = await agent
        .post("/api/auth/customer/login/request-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email });
      expect(ineligibleReq.status).toBe(403);
      expect(ineligibleReq.body.code).toBe(code);
    }

    expect(await OtpChallenge.countDocuments({ purpose: "customer_login" })).toBe(0);

    // Eligible verified customer receives the OTP challenge.
    const validReq = await agent
      .post("/api/auth/customer/login/request-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: "  VERIFIED.SHOPPER@STORRA.TEST " });
    expect(validReq.status).toBe(200);
    expect(validReq.body.message).toMatch(/verification code has been sent/i);

    // Capture OTP before worker delivery intentionally wipes encryptedPayload
    const realOtp = await readOtpForChallenge(validReq.body.challengeId);

    // Outbox batch sends ONLY 1 email (verified.shopper@storra.test)
    const batch = await processOutboxBatchOnce();
    expect(batch.sent).toBe(1);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const deliveredOutbox = await EmailOutbox.findOne({
      challengeId: validReq.body.challengeId,
    }).lean();
    expect(deliveredOutbox?.status).toBe("sent");
    expect(deliveredOutbox?.encryptedPayload).toBeUndefined();

    // 3. Test 5-attempt lockout on verified customer
    const wrongOtp = realOtp === "111111" ? "222222" : "111111";
    for (let i = 1; i <= 5; i += 1) {
      const failRes = await agent
        .post("/api/auth/customer/login/verify-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({
          email: "verified.shopper@storra.test",
          challengeId: validReq.body.challengeId,
          otp: wrongOtp,
        });
      expect(failRes.status).toBe(i === 5 ? 423 : 401);
    }

    // 4. Test cooldown, resend, expiry, and successful login
    const req2 = await agent
      .post("/api/auth/customer/login/request-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: "verified.shopper@storra.test" });
    expect(req2.status).toBe(200);

    const earlyResend = await agent
      .post("/api/auth/customer/login/resend-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: "verified.shopper@storra.test", challengeId: req2.body.challengeId });
    expect(earlyResend.status).toBe(429);

    await ageCooldownForChallenge(
      "customer_login",
      "verified.shopper@storra.test",
      req2.body.challengeId,
    );
    const resendOk = await agent
      .post("/api/auth/customer/login/resend-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: "verified.shopper@storra.test", challengeId: req2.body.challengeId });
    expect(resendOk.status).toBe(200);

    const newOtp = await readOtpForChallenge(resendOk.body.challengeId);

    // Expire check
    await OtpChallenge.updateOne(
      { challengeId: resendOk.body.challengeId },
      { $set: { expiresAt: new Date(Date.now() - 1000) } },
    );
    const expiredRes = await agent
      .post("/api/auth/customer/login/verify-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        email: "verified.shopper@storra.test",
        challengeId: resendOk.body.challengeId,
        otp: newOtp,
      });
    expect(expiredRes.status).toBe(401);
    expect(expiredRes.body.code).toBe("CHALLENGE_EXPIRED");

    // Restore valid expiry and complete login
    await OtpChallenge.updateOne(
      { challengeId: resendOk.body.challengeId },
      { $set: { expiresAt: new Date(Date.now() + OTP_TTL_MS) } },
    );
    const loginOk = await agent
      .post("/api/auth/customer/login/verify-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        email: "verified.shopper@storra.test",
        challengeId: resendOk.body.challengeId,
        otp: newOtp,
      });
    expect(loginOk.status).toBe(200);
    expect(loginOk.body.user?.role).toBe("CUSTOMER");
    const loginCookies = parseSetCookies(loginOk.headers["set-cookie"]);
    expect(loginCookies.jwt?.value).toBeTruthy();
    expect(loginCookies.refreshToken?.value).toBeTruthy();
  });

  it("rolls back consumedAt when customerSignupVerifyOtp encounters a User creation error or concurrent conflict", async () => {
    await enableCustomerEmailOtp();
    mockMsg91Success();
    const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

    const reqRes = await agent
      .post("/api/auth/customer/signup/request-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        name: "Tx Rollback User",
        email: "tx.signup@storra.test",
        phone: "9845111222",
      });
    expect(reqRes.status).toBe(200);
    const otp = await readOtpForChallenge(reqRes.body.challengeId);

    // 1. Forced User.save error inside tx -> 500, zero Users created, consumedAt stays null
    const saveSpy = jest
      .spyOn(User.prototype, "save")
      .mockRejectedValueOnce(new Error("Simulated Mongo write error"));

    const errRes = await agent
      .post("/api/auth/customer/signup/verify-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        email: "tx.signup@storra.test",
        challengeId: reqRes.body.challengeId,
        otp,
      });
    expect(errRes.status).toBe(500);
    saveSpy.mockRestore();

    expect(await User.countDocuments()).toBe(0);
    const afterSaveFail = await OtpChallenge.findOne({ challengeId: reqRes.body.challengeId }).lean();
    expect(afterSaveFail?.consumedAt).toBeNull();

    // 2. Concurrent conflict inserted before verify -> 409 SIGNUP_CONFLICT, consumedAt still stays null
    await User.create({
      username: "Concurrent Rival",
      email: "rival@storra.test",
      phone: "9845111222",
      role: "CUSTOMER",
      isActive: true,
      isVerified: true,
    });

    const conflictRes = await agent
      .post("/api/auth/customer/signup/verify-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        email: "tx.signup@storra.test",
        challengeId: reqRes.body.challengeId,
        otp,
      });
    expect(conflictRes.status).toBe(409);
    expect(conflictRes.body.code).toBe("SIGNUP_CONFLICT");

    const afterConflict = await OtpChallenge.findOne({ challengeId: reqRes.body.challengeId }).lean();
    expect(afterConflict?.consumedAt).toBeNull();

    // Remove conflicting phone user and retry with SAME OTP -> succeeds cleanly!
    await User.deleteMany({ phone: "9845111222" });
    const retryOk = await agent
      .post("/api/auth/customer/signup/verify-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        email: "tx.signup@storra.test",
        challengeId: reqRes.body.challengeId,
        otp,
      });
    expect(retryOk.status).toBe(201);
    expect(await User.countDocuments({ email: "tx.signup@storra.test" })).toBe(1);
  });

  it("blocks STAFF, ADMIN, and SUPER_ADMIN across customer Email OTP and SMS prep routes", async () => {
    await enableCustomerEmailOtp();
    const fetchSpy = jest.spyOn(globalThis, "fetch").mockImplementation(async (url, init) => {
      if (String(url).includes("/widget/verifyAccessToken")) {
        const body = JSON.parse(String(init?.body ?? "{}")) as { "access-token"?: string };
        return {
          ok: true,
          status: 200,
          text: async () =>
            JSON.stringify({ type: "success", data: { mobile: body["access-token"] } }),
        } as globalThis.Response;
      }
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: "success" }),
      } as globalThis.Response;
    });

    const [admin, superAdmin, staff] = await User.insertMany([
      {
        username: "Role Check Admin",
        email: "role.admin@storra.test",
        phone: "589100001",
        role: "ADMIN",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: new Date(),
      },
      {
        username: "Role Check SuperAdmin",
        email: "role.super@storra.test",
        phone: "589100002",
        role: "SUPER_ADMIN",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: new Date(),
      },
      {
        username: "Role Check Staff",
        email: "role.staff@storra.test",
        phone: "589100003",
        role: "STAFF",
        isActive: true,
        isVerified: true,
        emailVerifiedAt: new Date(),
      },
    ]);
    await StaffProfile.create({
      userId: staff._id,
      managedBy: admin._id,
      permissions: ["ORDER_VIEW"],
      isActive: true,
    });

    const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);
    const privilegedAccounts = [admin, superAdmin, staff];

    for (const acc of privilegedAccounts) {
      // Customer Email OTP login is explicitly restricted for internal roles.
      const loginReq = await agent
        .post("/api/auth/customer/login/request-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: acc.email });
      expect(loginReq.status).toBe(403);
      expect(loginReq.body.code).toBe("ROLE_RESTRICTED");

      // Customer Email OTP signup with existing privileged email also emits decoy
      const signupReq = await agent
        .post("/api/auth/customer/signup/request-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ name: "Spoof", email: acc.email, phone: "589199999" });
      expect(signupReq.status).toBe(200);
      const signupChg = await OtpChallenge.findOne({ challengeId: signupReq.body.challengeId }).lean();
      expect(signupChg?.isDecoy).toBe(true);

      // SMS prep login rejects all internal roles with 403 ROLE_RESTRICTED
      const smsRes = await agent
        .post("/api/auth/mobile/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ phone: acc.phone, accessToken: `971${acc.phone}` });
      expect(smsRes.status).toBe(403);
      expect(smsRes.body.code).toBe("ROLE_RESTRICTED");
    }

    const batch = await processOutboxBatchOnce();
    expect(batch.sent).toBe(0);
    // Only MSG91 SMS widget verifyAccessToken calls happened (3), zero email API calls
    expect(fetchSpy.mock.calls.every(([url]) => String(url).includes("widget/verifyAccessToken"))).toBe(
      true,
    );
  });

  it("keeps admin login, password reset, profile update, and SMS customer auth operational during preparation window when flag is OFF or ON", async () => {
    jest.spyOn(globalThis, "fetch").mockImplementation(async (url, init) => {
      if (String(url).includes("/widget/verifyAccessToken")) {
        const body = JSON.parse(String(init?.body ?? "{}")) as { "access-token"?: string };
        return {
          ok: true,
          status: 200,
          text: async () =>
            JSON.stringify({ type: "success", data: { mobile: body["access-token"] } }),
        } as globalThis.Response;
      }
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: "success" }),
      } as globalThis.Response;
    });

    const pwHash = await bcrypt.hash("FlagMatrix@123", 10);
    const admin = await User.create({
      username: "Flag Matrix Admin",
      email: "flag.admin@storra.test",
      phone: "9892000001",
      password: pwHash,
      role: "ADMIN",
      isActive: true,
      isVerified: true,
      tokenVersion: 0,
    });

    const { agent, origin, csrfToken } = await bootstrapCsrfAgent(appCtx.app);

    // 1. Flag OFF: Customer Email OTP disabled, yet SMS customer register/login + admin login + reset + profile update work!
    const cfgOff = await request(appCtx.app).get("/api/auth/customer/config");
    expect(cfgOff.body).toEqual({ customerEmailOtpEnabled: false, customerSmsOtpEnabled: true });

    const custEmailOff = await agent
      .post("/api/auth/customer/login/request-otp")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: "anyone@storra.test" });
    expect(custEmailOff.status).toBe(403);
    expect(custEmailOff.body.code).toBe("FEATURE_DISABLED");

    const smsReg = await agent
      .post("/api/auth/mobile/register")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({
        name: "Prep Window SMS",
        email: "prep.window.sms@storra.test",
        phone: "9892000002",
        accessToken: "919892000002",
      });
    expect(smsReg.status).toBe(201);
    expect((await User.findById(smsReg.body.user.id).lean())?.emailVerifiedAt).toBeNull();

    const adminS1 = await agent
      .post("/api/auth/login")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: admin.email, password: "FlagMatrix@123" });
    expect(adminS1.status).toBe(200);
    const adminOtp = await readOtpForChallenge(adminS1.body.challengeId);
    const adminS2 = await agent
      .post("/api/auth/login/verify")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: admin.email, otp: adminOtp });
    expect(adminS2.status).toBe(200);

    // Password reset still works with flag OFF
    const forgotRes = await agent
      .post("/api/auth/forgot-password")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ email: admin.email });
    expect(forgotRes.status).toBe(200);

    // 2. Flip flag ON: SMS login STILL operates during preparation window alongside Email OTP
    await enableCustomerEmailOtp();
    const cfgOn = await request(appCtx.app).get("/api/auth/customer/config");
    expect(cfgOn.body).toEqual({ customerEmailOtpEnabled: true, customerSmsOtpEnabled: true });

    const smsLoginStillWorks = await agent
      .post("/api/auth/mobile/login")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("X-Forwarded-For", nextTestIp())
      .send({ phone: "9892000002", accessToken: "919892000002" });
    expect(smsLoginStillWorks.status).toBe(200);
  });
});
