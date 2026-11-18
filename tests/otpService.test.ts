import crypto from "crypto";
import mongoose from "mongoose";
import { generateOtpCode } from "../src/config/mailer";
import {
  EmailOutbox,
  OtpChallenge,
  OtpRateLimit,
} from "../src/models/mongoose";
import {
  attachResetTokenJti,
  consumeRateLimitBucket,
  consumeResetTokenJti,
  ensureOtpCollectionsInitialized,
  issueChallengeAndEnqueueOutbox,
  OTP_MAX_ATTEMPTS,
  OTP_MAX_RESENDS,
  OTP_RESEND_COOLDOWN_MS,
  OTP_TTL_MS,
  resendChallengeAndEnqueueOutbox,
  verifyChallengeOtp,
} from "../src/services/otp.service";
import {
  computeOtpHmac,
  decryptOutboxPayload,
  verifyOtpHmacDigest,
} from "../src/utils/otpCrypto";
import { clearTestDb, startTestDb, stopTestDb } from "./helpers/testDb";

describe("PR 2 — Centralized OtpService (HMAC, concurrency, lockout, expiry, quotas & purpose isolation)", () => {
  beforeAll(async () => {
    await startTestDb();
    await ensureOtpCollectionsInitialized();
  });

  afterEach(async () => {
    jest.restoreAllMocks();
    await clearTestDb();
  });

  afterAll(async () => {
    await stopTestDb();
  });

  const readOtpFromOutbox = async (outboxId: string): Promise<string> => {
    const outbox = await EmailOutbox.findOne({ outboxId }).lean();
    expect(outbox).toBeTruthy();
    expect(outbox?.encryptedPayload).toBeTruthy();
    const decrypted = decryptOutboxPayload(outbox!.encryptedPayload!);
    expect(decrypted.variables.OTP).toMatch(/^\d{6}$/);
    return decrypted.variables.OTP;
  };

  it("generates strictly 6-digit OTPs via crypto.randomInt(100000, 1000000) and stores zero plaintext OTP in OtpChallenge", async () => {
    const spy = jest.spyOn(crypto, "randomInt");
    for (let i = 0; i < 50; i += 1) {
      const code = generateOtpCode();
      expect(code).toMatch(/^\d{6}$/);
      const num = Number(code);
      expect(num).toBeGreaterThanOrEqual(100000);
      expect(num).toBeLessThanOrEqual(999999);
    }
    expect(spy).toHaveBeenCalledWith(100000, 1000000);

    const issued = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: "  Alice.Test@Storra.TEST ",
      ip: "10.0.0.1",
    });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const challenge = await OtpChallenge.findOne({
      challengeId: issued.challengeId,
    }).lean();
    expect(challenge).toBeTruthy();
    expect(challenge?.email).toBe("alice.test@storra.test");
    expect(challenge?.otpHash).toMatch(/^[a-f0-9]{64}$/);
    expect((challenge as unknown as Record<string, unknown>).otp).toBeUndefined();

    const plaintextOtp = await readOtpFromOutbox(issued.outboxId);
    expect(JSON.stringify(challenge)).not.toContain(plaintextOtp);
  });

  it("computes length-prefixed HMAC digests bound to purpose, normalizedEmail, challengeId, challengeNonce & otp, and compares timing-safely", () => {
    const base = {
      purpose: "customer_signup" as const,
      normalizedEmail: "user@storra.test",
      challengeId: "chg_abc123",
      challengeNonce: "deadbeef01",
      otp: "482913",
    };

    const digest = computeOtpHmac(base);
    expect(digest).toMatch(/^[a-f0-9]{64}$/);
    expect(verifyOtpHmacDigest(base, digest)).toBe(true);
    expect(
      verifyOtpHmacDigest({ ...base, normalizedEmail: " USER@STORRA.TEST " }, digest),
    ).toBe(true);

    // Changing any bound component invalidates verification
    expect(verifyOtpHmacDigest({ ...base, purpose: "customer_login" }, digest)).toBe(false);
    expect(verifyOtpHmacDigest({ ...base, normalizedEmail: "other@storra.test" }, digest)).toBe(false);
    expect(verifyOtpHmacDigest({ ...base, challengeId: "chg_abc124" }, digest)).toBe(false);
    expect(verifyOtpHmacDigest({ ...base, challengeNonce: "deadbeef02" }, digest)).toBe(false);
    expect(verifyOtpHmacDigest({ ...base, otp: "482914" }, digest)).toBe(false);

    // Boundary ambiguity attack across fields prevented by byte-length framing
    const ambigA = computeOtpHmac({
      purpose: "a",
      normalizedEmail: "b|c",
      challengeId: "d",
      challengeNonce: "e",
      otp: "123456",
    });
    const ambigB = computeOtpHmac({
      purpose: "a|b",
      normalizedEmail: "c",
      challengeId: "d",
      challengeNonce: "e",
      otp: "123456",
    });
    expect(ambigA).not.toBe(ambigB);

    // Malformed / short digests fail cleanly without RangeError
    expect(verifyOtpHmacDigest(base, null)).toBe(false);
    expect(verifyOtpHmacDigest(base, undefined)).toBe(false);
    expect(verifyOtpHmacDigest(base, "short")).toBe(false);
    expect(verifyOtpHmacDigest(base, "g".repeat(64))).toBe(false);
  });

  it("enforces 5-attempt lockout, suppresses pending outbox on lock, and enforces explicit expiresAt check", async () => {
    const t0 = new Date();
    const issued = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: "lock.target@storra.test",
      ip: "10.0.0.2",
      now: t0,
    });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const realOtp = await readOtpFromOutbox(issued.outboxId);
    const wrongOtp = realOtp === "111111" ? "222222" : "111111";

    for (let i = 1; i <= 4; i += 1) {
      const failRes = await verifyChallengeOtp({
        purpose: "customer_login",
        email: "lock.target@storra.test",
        challengeId: issued.challengeId,
        otp: wrongOtp,
        ip: "10.0.0.2",
        now: new Date(t0.getTime() + i * 1000),
      });
      expect(failRes.ok).toBe(false);
      if (!failRes.ok) {
        expect(failRes.code).toBe("INVALID_OTP");
        expect(failRes.httpStatus).toBe(401);
        expect(failRes.attemptsRemaining).toBe(OTP_MAX_ATTEMPTS - i);
      }
    }

    // 5th failed attempt locks challenge and suppresses pending outbox
    const fifthRes = await verifyChallengeOtp({
      purpose: "customer_login",
      email: "lock.target@storra.test",
      challengeId: issued.challengeId,
      otp: wrongOtp,
      ip: "10.0.0.2",
      now: new Date(t0.getTime() + 5000),
    });
    expect(fifthRes.ok).toBe(false);
    if (!fifthRes.ok) {
      expect(fifthRes.code).toBe("CHALLENGE_LOCKED");
      expect(fifthRes.httpStatus).toBe(423);
      expect(fifthRes.attemptsRemaining).toBe(0);
    }

    const lockedDoc = await OtpChallenge.findOne({ challengeId: issued.challengeId }).lean();
    expect(lockedDoc?.attempts).toBe(5);
    expect(lockedDoc?.lockedAt).toBeTruthy();

    const suppressedOutbox = await EmailOutbox.findOne({ outboxId: issued.outboxId }).lean();
    expect(suppressedOutbox?.status).toBe("suppressed");
    expect(suppressedOutbox?.encryptedPayload).toBeUndefined();

    // Correct OTP cannot unlock an already-locked challenge
    const afterLockRes = await verifyChallengeOtp({
      purpose: "customer_login",
      email: "lock.target@storra.test",
      challengeId: issued.challengeId,
      otp: realOtp,
      ip: "10.0.0.2",
      now: new Date(t0.getTime() + 6000),
    });
    expect(afterLockRes.ok).toBe(false);
    if (!afterLockRes.ok) {
      expect(afterLockRes.code).toBe("CHALLENGE_LOCKED");
      expect(afterLockRes.httpStatus).toBe(423);
    }

    // Explicit expiry enforcement before MongoDB TTL sweep runs
    const expIssued = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_signup",
      email: "expiry.target@storra.test",
      ip: "10.0.0.3",
      now: t0,
    });
    expect(expIssued.ok).toBe(true);
    if (!expIssued.ok) return;

    const expOtp = await readOtpFromOutbox(expIssued.outboxId);
    const expiredAttempt = await verifyChallengeOtp({
      purpose: "customer_signup",
      email: "expiry.target@storra.test",
      challengeId: expIssued.challengeId,
      otp: expOtp,
      ip: "10.0.0.3",
      now: new Date(t0.getTime() + OTP_TTL_MS + 1000),
    });
    expect(expiredAttempt.ok).toBe(false);
    if (!expiredAttempt.ok) {
      expect(expiredAttempt.code).toBe("CHALLENGE_EXPIRED");
      expect(expiredAttempt.httpStatus).toBe(401);
    }
  });

  it("enforces strict cross-purpose isolation and userId / email / challenge / authVerified / tokenVersion binding", async () => {
    const userIdA = new mongoose.Types.ObjectId();
    const userIdB = new mongoose.Types.ObjectId();
    const issued = await issueChallengeAndEnqueueOutbox({
      purpose: "admin_login",
      email: "admin.bind@storra.test",
      userId: userIdA,
      authVerified: false,
      tokenVersionSnapshot: 2,
      ip: "10.0.0.4",
    });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const otp = await readOtpFromOutbox(issued.outboxId);

    // Every unrelated purpose must reject without consuming the challenge
    for (const wrongPurpose of [
      "customer_signup",
      "customer_login",
      "password_reset",
      "profile_update",
      "pos_counter_verify",
    ] as const) {
      const res = await verifyChallengeOtp({
        purpose: wrongPurpose,
        email: "admin.bind@storra.test",
        challengeId: issued.challengeId,
        otp,
        ip: "10.0.0.5",
      });
      expect(res.ok).toBe(false);
    }

    // Wrong email, wrong challengeId, wrong userId
    expect(
      (
        await verifyChallengeOtp({
          purpose: "admin_login",
          email: "other@storra.test",
          challengeId: issued.challengeId,
          userId: userIdA,
          otp,
          ip: "10.0.0.6",
        })
      ).ok,
    ).toBe(false);

    expect(
      (
        await verifyChallengeOtp({
          purpose: "admin_login",
          email: "admin.bind@storra.test",
          challengeId: issued.challengeId,
          userId: userIdB,
          otp,
          ip: "10.0.0.6",
        })
      ).ok,
    ).toBe(false);

    // authVerified=false rejected when requireAuthVerified=true
    const unauthRes = await verifyChallengeOtp({
      purpose: "admin_login",
      email: "admin.bind@storra.test",
      challengeId: issued.challengeId,
      userId: userIdA,
      requireAuthVerified: true,
      otp,
      ip: "10.0.0.6",
    });
    expect(unauthRes.ok).toBe(false);
    if (!unauthRes.ok) expect(unauthRes.code).toBe("AUTH_NOT_VERIFIED");

    // Stale tokenVersion rejected
    const staleVersionRes = await verifyChallengeOtp({
      purpose: "admin_login",
      email: "admin.bind@storra.test",
      challengeId: issued.challengeId,
      userId: userIdA,
      expectedTokenVersion: 3,
      otp,
      ip: "10.0.0.6",
    });
    expect(staleVersionRes.ok).toBe(false);
    if (!staleVersionRes.ok) expect(staleVersionRes.code).toBe("TOKEN_VERSION_MISMATCH");

    // Challenge itself is STILL unconsumed and valid when all bindings match
    const validRes = await verifyChallengeOtp({
      purpose: "admin_login",
      email: "admin.bind@storra.test",
      challengeId: issued.challengeId,
      userId: userIdA,
      expectedTokenVersion: 2,
      otp,
      ip: "10.0.0.6",
    });
    expect(validRes.ok).toBe(true);
  });

  it("allows strictly ONE single-use consumption under concurrent verify calls and caps concurrent wrong attempts at 5", async () => {
    // 1. Concurrent valid verification race (8 parallel calls -> 1 succeeds, 7 fail)
    const issuedValid = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: "race.valid@storra.test",
      ip: "10.0.0.10",
    });
    expect(issuedValid.ok).toBe(true);
    if (!issuedValid.ok) return;

    const validOtp = await readOtpFromOutbox(issuedValid.outboxId);
    const validResults = await Promise.all(
      Array.from({ length: 8 }, (_, idx) =>
        verifyChallengeOtp({
          purpose: "customer_login",
          email: "race.valid@storra.test",
          challengeId: issuedValid.challengeId,
          otp: validOtp,
          ip: `10.0.1.${idx + 1}`,
        }),
      ),
    );

    const successes = validResults.filter((r) => r.ok);
    const failures = validResults.filter((r) => !r.ok);
    expect(successes).toHaveLength(1);
    expect(failures).toHaveLength(7);

    // 2. Concurrent invalid verification race (10 parallel calls -> attempts never exceed maxAttempts=5 and locks)
    const issuedWrong = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: "race.wrong@storra.test",
      ip: "10.0.0.11",
    });
    expect(issuedWrong.ok).toBe(true);
    if (!issuedWrong.ok) return;

    const realOtp = await readOtpFromOutbox(issuedWrong.outboxId);
    const wrongOtp = realOtp === "999999" ? "888888" : "999999";

    const wrongResults = await Promise.all(
      Array.from({ length: 10 }, (_, idx) =>
        verifyChallengeOtp({
          purpose: "customer_login",
          email: "race.wrong@storra.test",
          challengeId: issuedWrong.challengeId,
          otp: wrongOtp,
          ip: `10.0.2.${idx + 1}`,
        }),
      ),
    );

    expect(wrongResults.every((r) => !r.ok)).toBe(true);
    const wrongChallenge = await OtpChallenge.findOne({
      challengeId: issuedWrong.challengeId,
    }).lean();
    expect(wrongChallenge?.attempts).toBe(OTP_MAX_ATTEMPTS);
    expect(wrongChallenge?.lockedAt).toBeTruthy();

    // Real OTP is blocked after concurrent brute force
    const postRaceValid = await verifyChallengeOtp({
      purpose: "customer_login",
      email: "race.wrong@storra.test",
      challengeId: issuedWrong.challengeId,
      otp: realOtp,
      ip: "10.0.2.99",
    });
    expect(postRaceValid.ok).toBe(false);
    if (!postRaceValid.ok) {
      expect(postRaceValid.code).toBe("CHALLENGE_LOCKED");
    }
  });

  it("handles concurrent consumeRateLimitBucket quotas accurately and resets expired buckets cleanly", async () => {
    const start = new Date();
    const key = "test_bucket:email:concurrent@storra.test";

    const concurrent = await Promise.all(
      Array.from({ length: 12 }, () =>
        consumeRateLimitBucket({
          key,
          scope: "test",
          limit: 5,
          windowMs: 60_000,
          now: start,
        }),
      ),
    );

    const allowed = concurrent.filter((r) => r.allowed);
    const denied = concurrent.filter((r) => !r.allowed);
    expect(allowed).toHaveLength(5);
    expect(denied).toHaveLength(7);

    const doc = await OtpRateLimit.findOne({ key }).lean();
    expect(doc?.count).toBe(5);

    // Rotating caller IPs still cannot bypass per-email issuance quota (8 per 15m)
    const issuedIds: string[] = [];
    for (let i = 0; i < 8; i += 1) {
      const res = await issueChallengeAndEnqueueOutbox({
        purpose: "customer_login",
        email: "quota.email@storra.test",
        ip: `10.50.0.${i + 1}`,
        now: new Date(start.getTime() + i * 1000),
      });
      expect(res.ok).toBe(true);
      if (res.ok) issuedIds.push(res.challengeId);
    }
    expect(issuedIds).toHaveLength(8);

    // Only the latest challenge remains active; all prior 7 were invalidated
    const activeCount = await OtpChallenge.countDocuments({
      email: "quota.email@storra.test",
      invalidatedAt: null,
    });
    expect(activeCount).toBe(1);

    const ninthRes = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: "quota.email@storra.test",
      ip: "10.50.0.99",
      now: new Date(start.getTime() + 9000),
    });
    expect(ninthRes.ok).toBe(false);
    if (!ninthRes.ok) {
      expect(ninthRes.code).toBe("RATE_LIMITED");
      expect(ninthRes.httpStatus).toBe(429);
    }

    // Expired bucket resets count cleanly back to 1
    const afterExpiry = await consumeRateLimitBucket({
      key,
      scope: "test",
      limit: 5,
      windowMs: 60_000,
      now: new Date(start.getTime() + 65_000),
    });
    expect(afterExpiry.allowed).toBe(true);
    if (afterExpiry.allowed) {
      expect(afterExpiry.remaining).toBe(4);
    }
    expect((await OtpRateLimit.findOne({ key }).lean())?.count).toBe(1);
  });

  it("enforces 120s resend cooldown, max 3 resends, and single-use resetTokenJti lifecycle", async () => {
    const base = new Date();
    const initial = await issueChallengeAndEnqueueOutbox({
      purpose: "password_reset",
      email: "reset.flow@storra.test",
      userId: new mongoose.Types.ObjectId(),
      ip: "10.60.0.1",
      now: base,
    });
    expect(initial.ok).toBe(true);
    if (!initial.ok) return;

    // Immediate resend hits 120s cooldown
    const tooEarly = await resendChallengeAndEnqueueOutbox({
      purpose: "password_reset",
      email: "reset.flow@storra.test",
      challengeId: initial.challengeId,
      ip: "10.60.0.1",
      now: new Date(base.getTime() + 30_000),
    });
    expect(tooEarly.ok).toBe(false);
    if (!tooEarly.ok) expect(tooEarly.code).toBe("RESEND_COOLDOWN");

    // 3 resends allowed after each 120s cooldown; 4th denied with MAX_RESENDS_EXCEEDED
    let activeChallengeId = initial.challengeId;
    let activeOutboxId = initial.outboxId;
    for (let r = 1; r <= OTP_MAX_RESENDS; r += 1) {
      const stepNow = new Date(base.getTime() + r * (OTP_RESEND_COOLDOWN_MS + 1000));
      const res = await resendChallengeAndEnqueueOutbox({
        purpose: "password_reset",
        email: "reset.flow@storra.test",
        challengeId: activeChallengeId,
        ip: "10.60.0.1",
        now: stepNow,
      });
      expect(res.ok).toBe(true);
      if (res.ok) {
        const oldDoc = await OtpChallenge.findOne({ challengeId: activeChallengeId }).lean();
        expect(oldDoc?.invalidatedAt).toBeTruthy();
        activeChallengeId = res.challengeId;
        activeOutboxId = res.outboxId;
      }
    }

    const fourthResend = await resendChallengeAndEnqueueOutbox({
      purpose: "password_reset",
      email: "reset.flow@storra.test",
      challengeId: activeChallengeId,
      ip: "10.60.0.1",
      now: new Date(base.getTime() + 4 * (OTP_RESEND_COOLDOWN_MS + 1000)),
    });
    expect(fourthResend.ok).toBe(false);
    if (!fourthResend.ok) expect(fourthResend.code).toBe("MAX_RESENDS_EXCEEDED");

    // Verify latest challenge & test single-use resetTokenJti consumption
    const finalOtp = await readOtpFromOutbox(activeOutboxId);
    const verified = await verifyChallengeOtp({
      purpose: "password_reset",
      email: "reset.flow@storra.test",
      challengeId: activeChallengeId,
      otp: finalOtp,
      ip: "10.60.0.1",
      now: new Date(base.getTime() + 3 * (OTP_RESEND_COOLDOWN_MS + 1000) + 5000),
    });
    expect(verified.ok).toBe(true);
    if (!verified.ok) return;

    const uid = new mongoose.Types.ObjectId();
    const jti = await attachResetTokenJti({
      challengeObjectId: verified.challenge._id as mongoose.Types.ObjectId,
      userId: uid,
    });
    expect(jti?.jti).toBeTruthy();

    // Attaching a second JTI to the same consumed challenge returns null
    const secondJti = await attachResetTokenJti({
      challengeObjectId: verified.challenge._id as mongoose.Types.ObjectId,
      userId: uid,
    });
    expect(secondJti).toBeNull();

    const firstConsume = await consumeResetTokenJti({
      jti: jti!.jti,
      email: "reset.flow@storra.test",
      userId: uid,
    });
    expect(firstConsume.ok).toBe(true);

    const replayConsume = await consumeResetTokenJti({
      jti: jti!.jti,
      email: "reset.flow@storra.test",
      userId: uid,
    });
    expect(replayConsume.ok).toBe(false);
    if (!replayConsume.ok) expect(replayConsume.code).toBe("RESET_TOKEN_USED");
  });

  it("enforces complete 6x6 cross-purpose isolation across all OtpPurpose values", async () => {
    const allPurposes = [
      "customer_signup",
      "customer_login",
      "admin_login",
      "password_reset",
      "profile_update",
      "pos_counter_verify",
    ] as const;

    const sharedEmail = "matrix.isolation@storra.test";
    const sharedUserId = new mongoose.Types.ObjectId();
    const issuedMap = new Map<
      (typeof allPurposes)[number],
      { challengeId: string; outboxId: string; otp: string }
    >();

    for (const purpose of allPurposes) {
      const issued = await issueChallengeAndEnqueueOutbox({
        purpose,
        email: sharedEmail,
        userId: sharedUserId,
        authVerified: true,
        ip: "10.70.0.1",
      });
      expect(issued.ok).toBe(true);
      if (!issued.ok) return;
      const otp = await readOtpFromOutbox(issued.outboxId);
      issuedMap.set(purpose, {
        challengeId: issued.challengeId,
        outboxId: issued.outboxId,
        otp,
      });
    }

    // A) With challengeId supplied across all 30 mismatched (source, target) pairs:
    //    must reject with CHALLENGE_INVALID without touching attempts or consumedAt
    for (const sourcePurpose of allPurposes) {
      const src = issuedMap.get(sourcePurpose)!;
      for (const targetPurpose of allPurposes) {
        if (sourcePurpose === targetPurpose) continue;
        const mismatchById = await verifyChallengeOtp({
          purpose: targetPurpose,
          email: sharedEmail,
          challengeId: src.challengeId,
          userId: sharedUserId,
          otp: src.otp,
          ip: "10.70.0.2",
        });
        expect(mismatchById.ok).toBe(false);
        if (!mismatchById.ok) expect(mismatchById.code).toBe("CHALLENGE_INVALID");
      }
    }

    // B) Without challengeId when a target purpose already has its own active challenge:
    //    submitting sourcePurpose OTP against targetPurpose only checks targetPurpose's HMAC
    //    (rejecting with INVALID_OTP without consuming either challenge)
    for (let i = 0; i < allPurposes.length; i += 1) {
      const sourcePurpose = allPurposes[i];
      const targetPurpose = allPurposes[(i + 1) % allPurposes.length];
      const src = issuedMap.get(sourcePurpose)!;
      const mismatchWithoutId = await verifyChallengeOtp({
        purpose: targetPurpose,
        email: sharedEmail,
        userId: sharedUserId,
        otp: src.otp,
        ip: "10.70.0.2",
      });
      expect(mismatchWithoutId.ok).toBe(false);
      if (!mismatchWithoutId.ok) expect(mismatchWithoutId.code).toBe("INVALID_OTP");
    }

    // C) Without challengeId when targetPurpose has NO active challenge (isolated email + userId per source):
    //    none of the other 5 purposes can locate or verify sourcePurpose's challenge
    for (const sourcePurpose of allPurposes) {
      const isolatedEmail = `matrix.noid.${sourcePurpose}@storra.test`;
      const isolatedUserId = new mongoose.Types.ObjectId();
      const isoIssued = await issueChallengeAndEnqueueOutbox({
        purpose: sourcePurpose,
        email: isolatedEmail,
        userId: isolatedUserId,
        authVerified: true,
        ip: "10.70.0.4",
      });
      expect(isoIssued.ok).toBe(true);
      if (!isoIssued.ok) return;
      const isoOtp = await readOtpFromOutbox(isoIssued.outboxId);
      for (const targetPurpose of allPurposes) {
        if (sourcePurpose === targetPurpose) continue;
        const noIdRes = await verifyChallengeOtp({
          purpose: targetPurpose,
          email: isolatedEmail,
          userId: isolatedUserId,
          otp: isoOtp,
          ip: "10.70.0.4",
        });
        expect(noIdRes.ok).toBe(false);
        if (!noIdRes.ok) expect(noIdRes.code).toBe("CHALLENGE_INVALID");
      }
    }

    // D) All 6 shared challenges must STILL be active/unconsumed and succeed strictly under their own purpose
    for (const purpose of allPurposes) {
      const src = issuedMap.get(purpose)!;
      const doc = await OtpChallenge.findOne({ challengeId: src.challengeId }).lean();
      expect(doc?.consumedAt).toBeNull();
      expect(doc?.invalidatedAt).toBeNull();
      expect(doc?.attempts).toBe(1);

      const validRes = await verifyChallengeOtp({
        purpose,
        email: sharedEmail,
        challengeId: src.challengeId,
        userId: sharedUserId,
        otp: src.otp,
        ip: "10.70.0.3",
      });
      expect(validRes.ok).toBe(true);
    }
  });
});

