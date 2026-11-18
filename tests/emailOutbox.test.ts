import { env } from "../src/config/env";
import { EmailOutbox, OtpChallenge } from "../src/models/mongoose";
import logger from "../src/utils/logger";
import {
  claimNextEmailOutboxJob,
  processOutboxBatchOnce,
  startEmailOutboxWorker,
  stopEmailOutboxWorker,
} from "../src/services/emailOutbox.service";
import {
  ensureOtpCollectionsInitialized,
  issueChallengeAndEnqueueOutbox,
  OTP_RESEND_COOLDOWN_MS,
  resendChallengeAndEnqueueOutbox,
  verifyChallengeOtp,
} from "../src/services/otp.service";
import {
  assertOtpCryptoReady,
  decryptOutboxPayload,
  encryptOutboxPayload,
} from "../src/utils/otpCrypto";
import { clearTestDb, startTestDb, stopTestDb } from "./helpers/testDb";

describe("PR 2 — Persistent EmailOutbox & AES-256-GCM worker delivery", () => {
  beforeAll(async () => {
    await startTestDb();
    await ensureOtpCollectionsInitialized();
  });

  afterEach(async () => {
    await stopEmailOutboxWorker();
    jest.restoreAllMocks();
    await clearTestDb();
  });

  afterAll(async () => {
    await stopEmailOutboxWorker();
    await stopTestDb();
  });

  it("encrypts payloads with AES-256-GCM, rejects wrong keys / tampered tags, and enforces key separation from OTP_HMAC_SECRET", () => {
    const ciphertext = encryptOutboxPayload({
      to: "shopper@storra.test",
      toName: "Shopper",
      templateId: "tmpl_otp_test",
      variables: { OTP: "654321", EXPIRY_MINUTES: "5", PURPOSE: "log in to your account" },
    });

    expect(ciphertext.startsWith("v1:")).toBe(true);
    expect(ciphertext).not.toContain("654321");
    expect(ciphertext).not.toContain("shopper@storra.test");

    const plain = decryptOutboxPayload(ciphertext);
    expect(plain.to).toBe("shopper@storra.test");
    expect(plain.variables.OTP).toBe("654321");

    // Wrong OUTBOX_ENC_KEY fails authenticated decryption
    const origKey = env.OUTBOX_ENC_KEY;
    const origHmac = env.OTP_HMAC_SECRET;
    try {
      env.OUTBOX_ENC_KEY = "f".repeat(64);
      expect(() => decryptOutboxPayload(ciphertext)).toThrow();

      // Reusing OTP_HMAC_SECRET as OUTBOX_ENC_KEY fails key-separation guard
      env.OTP_HMAC_SECRET = "f".repeat(64);
      expect(() => assertOtpCryptoReady()).toThrow(/must NOT reuse OTP_HMAC_SECRET/i);
    } finally {
      env.OUTBOX_ENC_KEY = origKey;
      env.OTP_HMAC_SECRET = origHmac;
    }

    // Tampered auth tag fails GCM verification
    const parts = ciphertext.split(":");
    parts[2] = (parts[2][0] === "0" ? "1" : "0") + parts[2].slice(1);
    expect(() => decryptOutboxPayload(parts.join(":"))).toThrow();
  });

  it("claims outbox jobs atomically without duplicate sends under multi-worker contention and unsets encryptedPayload on success", async () => {
    const issuedIds: string[] = [];
    for (let i = 1; i <= 3; i += 1) {
      const res = await issueChallengeAndEnqueueOutbox({
        purpose: "customer_login",
        email: `worker${i}@storra.test`,
        ip: `10.1.0.${i}`,
      });
      expect(res.ok).toBe(true);
      if (res.ok) issuedIds.push(res.challengeId);
    }

    const sentPayloads: Array<{ to: string; otp: string }> = [];
    const fetchSpy = jest.spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
      await new Promise((r) => setTimeout(r, 25));
      const body = JSON.parse(String(init?.body ?? "{}")) as {
        recipients?: Array<{ to?: Array<{ email?: string }>; variables?: { OTP?: string } }>;
      };
      const email = body.recipients?.[0]?.to?.[0]?.email ?? "";
      const otp = body.recipients?.[0]?.variables?.OTP ?? "";
      sentPayloads.push({ to: email, otp });
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: "success", message: "queued" }),
      } as globalThis.Response;
    });

    // Simulate 6 Passenger worker processes racing simultaneously
    const summaries = await Promise.all(
      Array.from({ length: 6 }, (_, w) =>
        processOutboxBatchOnce({ workerId: `passenger-worker-${w + 1}`, batchSize: 10 }),
      ),
    );

    const totalClaimed = summaries.reduce((acc, s) => acc + s.claimed, 0);
    const totalSent = summaries.reduce((acc, s) => acc + s.sent, 0);
    expect(totalClaimed).toBe(3);
    expect(totalSent).toBe(3);
    expect(fetchSpy).toHaveBeenCalledTimes(3);
    expect(sentPayloads.map((p) => p.to).sort()).toEqual([
      "worker1@storra.test",
      "worker2@storra.test",
      "worker3@storra.test",
    ]);

    // Verify encryptedPayload was unset cleanly after delivery
    for (const challengeId of issuedIds) {
      const challenge = await OtpChallenge.findOne({ challengeId }).lean();
      const outbox = await EmailOutbox.findOne({ challengeId }).lean();
      expect(challenge?.deliveryStatus).toBe("sent");
      expect(outbox?.status).toBe("sent");
      expect(outbox?.sentAt).toBeTruthy();
      expect(outbox?.encryptedPayload).toBeUndefined();
      expect("encryptedPayload" in (outbox as unknown as Record<string, unknown>)).toBe(false);
    }
  });

  it("recovers stale processing locks for live jobs and fails exhausted stale jobs", async () => {
    const t0 = new Date();
    const recoverable = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: "stale.recover@storra.test",
      ip: "10.2.0.1",
      now: t0,
    });
    const exhausted = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: "stale.exhausted@storra.test",
      ip: "10.2.0.2",
      now: t0,
    });
    expect(recoverable.ok && exhausted.ok).toBe(true);
    if (!recoverable.ok || !exhausted.ok) return;

    const staleTime = new Date(t0.getTime() - 120_000);
    await EmailOutbox.updateOne(
      { outboxId: recoverable.outboxId },
      {
        $set: {
          status: "processing",
          lockedBy: "crashed-worker-1",
          lockedAt: staleTime,
          attempts: 1,
        },
      },
    );
    await EmailOutbox.updateOne(
      { outboxId: exhausted.outboxId },
      {
        $set: {
          status: "processing",
          lockedBy: "crashed-worker-2",
          lockedAt: staleTime,
          attempts: 3,
          maxAttempts: 3,
        },
      },
    );

    const fetchSpy = jest.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ status: "success" }),
    } as globalThis.Response);

    const summary = await processOutboxBatchOnce({
      workerId: "recovery-worker",
      now: t0,
      staleLockMs: 60_000,
    });

    expect(summary.claimed).toBe(1);
    expect(summary.sent).toBe(1);
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    const recoveredOutbox = await EmailOutbox.findOne({ outboxId: recoverable.outboxId }).lean();
    expect(recoveredOutbox?.status).toBe("sent");
    expect(recoveredOutbox?.attempts).toBe(2);
    expect(recoveredOutbox?.encryptedPayload).toBeUndefined();

    const exhaustedOutbox = await EmailOutbox.findOne({ outboxId: exhausted.outboxId }).lean();
    expect(exhaustedOutbox?.status).toBe("failed");
    expect(exhaustedOutbox?.errorCode).toBe("STALE_LOCK_EXHAUSTED");
    expect(exhaustedOutbox?.encryptedPayload).toBeUndefined();
  });

  it("never calls fetch for suppressed decoy outbox items or inactive challenges", async () => {
    const decoy = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: "decoy@storra.test",
      isDecoy: true,
      ip: "10.3.0.1",
    });
    expect(decoy.ok).toBe(true);
    if (!decoy.ok) return;

    const decoyOutbox = await EmailOutbox.findOne({ outboxId: decoy.outboxId }).lean();
    expect(decoyOutbox?.status).toBe("suppressed");
    expect(decoyOutbox?.encryptedPayload).toBeNull();

    // Real challenge invalidated before worker claims its pending outbox -> suppressed without sending
    const invalidatedReal = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: "invalidated.before.claim@storra.test",
      ip: "10.3.0.2",
    });
    expect(invalidatedReal.ok).toBe(true);
    if (!invalidatedReal.ok) return;

    await OtpChallenge.updateOne(
      { challengeId: invalidatedReal.challengeId },
      { $set: { invalidatedAt: new Date() } },
    );

    const fetchSpy = jest.spyOn(globalThis, "fetch");
    const summary = await processOutboxBatchOnce({ workerId: "suppressed-check-worker" });
    expect(summary.suppressed).toBe(1);
    expect(summary.sent).toBe(0);
    expect(fetchSpy).not.toHaveBeenCalled();

    const postOutbox = await EmailOutbox.findOne({ outboxId: invalidatedReal.outboxId }).lean();
    expect(postOutbox?.status).toBe("suppressed");
    expect(postOutbox?.encryptedPayload).toBeUndefined();
  });

  it("handles permanent provider errors (HTTP 4xx & HTTP 200 JSON error), definite transient retries with backoff limits, and ambiguous_timeout without auto-retry", async () => {
    // 1. Permanent HTTP 200 JSON error -> immediate failed, payload cleaned up
    const permRes = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: "perm.err@storra.test",
      ip: "10.4.0.1",
    });
    expect(permRes.ok).toBe(true);
    if (!permRes.ok) return;

    jest.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ hasError: true, type: "error", message: "Bad template" }),
    } as globalThis.Response);

    const permSummary = await processOutboxBatchOnce({ workerId: "perm-worker" });
    expect(permSummary.failed).toBe(1);
    const permOutbox = await EmailOutbox.findOne({ outboxId: permRes.outboxId }).lean();
    expect(permOutbox?.status).toBe("failed");
    expect(permOutbox?.errorCode).toBe("PROVIDER_REJECTED");
    expect(permOutbox?.encryptedPayload).toBeUndefined();
    expect((await OtpChallenge.findOne({ challengeId: permRes.challengeId }).lean())?.deliveryStatus).toBe(
      "failed",
    );

    // 2. Transient HTTP 500 -> retries same OTP with backoff up to maxAttempts=3, then fails
    const transRes = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: "transient@storra.test",
      ip: "10.4.0.2",
    });
    expect(transRes.ok).toBe(true);
    if (!transRes.ok) return;

    const firstOutboxSnap = await EmailOutbox.findOne({ outboxId: transRes.outboxId }).lean();
    const originalOtp = decryptOutboxPayload(firstOutboxSnap!.encryptedPayload!).variables.OTP;

    const sentOtps: string[] = [];
    jest.spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? "{}")) as {
        recipients?: Array<{ variables?: { OTP?: string } }>;
      };
      sentOtps.push(body.recipients?.[0]?.variables?.OTP ?? "");
      return {
        ok: false,
        status: 503,
        text: async () => JSON.stringify({ message: "Service Unavailable" }),
      } as globalThis.Response;
    });

    const tStart = new Date();
    const try1 = await processOutboxBatchOnce({ workerId: "trans-worker", now: tStart });
    expect(try1.retried).toBe(1);
    let docAfter1 = await EmailOutbox.findOne({ outboxId: transRes.outboxId }).lean();
    expect(docAfter1?.status).toBe("pending");
    expect(docAfter1?.attempts).toBe(1);
    expect(docAfter1?.encryptedPayload).toBeTruthy();

    // Advance past backoff window twice until maxAttempts (3) exhausted
    const try2 = await processOutboxBatchOnce({
      workerId: "trans-worker",
      now: new Date(Date.now() + 10_000),
    });
    expect(try2.retried).toBe(1);

    const try3 = await processOutboxBatchOnce({
      workerId: "trans-worker",
      now: new Date(Date.now() + 30_000),
    });
    expect(try3.failed).toBe(1);

    expect(sentOtps).toEqual([originalOtp, originalOtp, originalOtp]);
    const finalTransOutbox = await EmailOutbox.findOne({ outboxId: transRes.outboxId }).lean();
    expect(finalTransOutbox?.status).toBe("failed");
    expect(finalTransOutbox?.attempts).toBe(3);
    expect(finalTransOutbox?.encryptedPayload).toBeUndefined();

    // 3. Ambiguous timeout -> marks ambiguous_timeout, preserves challenge validity, no auto-retry, allows explicit Resend
    const tBase = new Date();
    const ambigRes = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: "ambiguous@storra.test",
      ip: "10.4.0.3",
      now: tBase,
    });
    expect(ambigRes.ok).toBe(true);
    if (!ambigRes.ok) return;

    const ambigPreSnap = await EmailOutbox.findOne({ outboxId: ambigRes.outboxId }).lean();
    const ambigOtp = decryptOutboxPayload(ambigPreSnap!.encryptedPayload!).variables.OTP;

    jest.spyOn(globalThis, "fetch").mockImplementationOnce(async () => {
      const abortErr = new Error("Request aborted due to timeout");
      abortErr.name = "AbortError";
      throw abortErr;
    });

    const ambigBatch = await processOutboxBatchOnce({ workerId: "ambig-worker", now: tBase });
    expect(ambigBatch.ambiguousTimeout).toBe(1);

    const ambigOutbox = await EmailOutbox.findOne({ outboxId: ambigRes.outboxId }).lean();
    expect(ambigOutbox?.status).toBe("ambiguous_timeout");
    expect(ambigOutbox?.encryptedPayload).toBeUndefined();
    expect(await claimNextEmailOutboxJob({ workerId: "ambig-worker-2" })).toBeNull();

    const ambigChallenge = await OtpChallenge.findOne({
      challengeId: ambigRes.challengeId,
    }).lean();
    expect(ambigChallenge?.deliveryStatus).toBe("ambiguous_timeout");

    // Existing OTP remains verifiable if the timed-out email actually arrived at the inbox
    // First test explicit Resend on an ambiguous challenge creates replacement & invalidates old
    const resendAfterAmbig = await resendChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: "ambiguous@storra.test",
      challengeId: ambigRes.challengeId,
      ip: "10.4.0.3",
      now: new Date(tBase.getTime() + OTP_RESEND_COOLDOWN_MS + 1000),
    });
    expect(resendAfterAmbig.ok).toBe(true);
    if (!resendAfterAmbig.ok) return;

    const newOutbox = await EmailOutbox.findOne({ outboxId: resendAfterAmbig.outboxId }).lean();
    const newOtp = decryptOutboxPayload(newOutbox!.encryptedPayload!).variables.OTP;

    // Old timed-out challenge was invalidated; replacement succeeds!
    const verifyOld = await verifyChallengeOtp({
      purpose: "customer_login",
      email: "ambiguous@storra.test",
      challengeId: ambigRes.challengeId,
      otp: ambigOtp,
      ip: "10.4.0.3",
    });
    expect(verifyOld.ok).toBe(false);

    const verifyNew = await verifyChallengeOtp({
      purpose: "customer_login",
      email: "ambiguous@storra.test",
      challengeId: resendAfterAmbig.challengeId,
      otp: newOtp,
      ip: "10.4.0.3",
    });
    expect(verifyNew.ok).toBe(true);
  });

  it("shuts down background worker gracefully while awaiting active inflight delivery batch", async () => {
    const issued = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: "shutdown@storra.test",
      ip: "10.5.0.1",
    });
    expect(issued.ok).toBe(true);

    const fetchHolder: { resolve: ((value: globalThis.Response) => void) | null } = {
      resolve: null,
    };
    let markFetchStarted!: () => void;
    const fetchStartedPromise = new Promise<void>((resolve) => {
      markFetchStarted = resolve;
    });
    let fetchStarted = false;
    jest.spyOn(globalThis, "fetch").mockImplementation(
      () =>
        new Promise((resolve) => {
          fetchStarted = true;
          fetchHolder.resolve = resolve;
          markFetchStarted();
        }),
    );

    startEmailOutboxWorker();
    try {
      await Promise.race([
        fetchStartedPromise,
        new Promise<void>((r) => setTimeout(r, 5000)),
      ]);
      expect(fetchStarted).toBe(true);

      let shutdownCompleted = false;
      const shutdownPromise = stopEmailOutboxWorker().then(() => {
        shutdownCompleted = true;
      });

      await new Promise((r) => setTimeout(r, 20));
      expect(shutdownCompleted).toBe(false);

      fetchHolder.resolve?.({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: "success" }),
      } as globalThis.Response);
      fetchHolder.resolve = null;

      await shutdownPromise;
      expect(shutdownCompleted).toBe(true);
    } finally {
      if (fetchHolder.resolve) {
        fetchHolder.resolve({
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ status: "success" }),
        } as globalThis.Response);
        fetchHolder.resolve = null;
      }
      await stopEmailOutboxWorker();
    }
  });

  it("keeps cleanupAt null for pending/processing/retried outbox jobs, stamps cleanupAt only on terminal states with partial TTL index, and never logs OTPs or secrets", async () => {
    const indexes = await EmailOutbox.collection.indexes();
    const partialTtlIdx = indexes.find((i) => i.name === "email_outbox_terminal_cleanup_ttl");
    expect(partialTtlIdx).toBeTruthy();
    expect(partialTtlIdx?.expireAfterSeconds).toBe(0);
    expect(partialTtlIdx?.partialFilterExpression).toEqual({
      status: { $in: ["sent", "failed", "suppressed", "ambiguous_timeout"] },
    });

    const t0 = new Date();
    const issued = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: "ttl.safety@storra.test",
      ip: "10.6.0.1",
      now: t0,
    });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    // 1. Fresh pending outbox has cleanupAt: null (cannot expire via TTL while queued)
    const pendingSnap = await EmailOutbox.findOne({ outboxId: issued.outboxId }).lean();
    expect(pendingSnap?.status).toBe("pending");
    expect(pendingSnap?.cleanupAt).toBeNull();
    const realOtp = decryptOutboxPayload(pendingSnap!.encryptedPayload!).variables.OTP;

    // Decoy outbox starts suppressed directly (terminal) and gets cleanupAt
    const decoyIssued = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: "ttl.decoy@storra.test",
      isDecoy: true,
      ip: "10.6.0.2",
      now: t0,
    });
    expect(decoyIssued.ok).toBe(true);
    if (decoyIssued.ok) {
      const decoySnap = await EmailOutbox.findOne({ outboxId: decoyIssued.outboxId }).lean();
      expect(decoySnap?.status).toBe("suppressed");
      expect(decoySnap?.cleanupAt).toBeInstanceOf(Date);
    }

    // 2. Claimed processing job keeps cleanupAt: null while worker owns it
    const claimed = await claimNextEmailOutboxJob({ workerId: "ttl-claim-worker", now: t0 });
    expect(claimed?.outboxId).toBe(issued.outboxId);
    expect(claimed?.status).toBe("processing");
    expect(claimed?.cleanupAt).toBeNull();

    // Release back to pending (simulating retryable state before terminal delivery) and verify transient retry keeps cleanupAt: null
    await EmailOutbox.updateOne(
      { outboxId: issued.outboxId },
      { $set: { status: "pending", lockedAt: null, lockedBy: null, attempts: 0 } },
    );

    const logMessages: string[] = [];
    const infoSpy = jest.spyOn(logger, "info").mockImplementation(((...args: unknown[]) => {
      logMessages.push(JSON.stringify(args));
      return logger;
    }) as never);
    const warnSpy = jest.spyOn(logger, "warn").mockImplementation(((...args: unknown[]) => {
      logMessages.push(JSON.stringify(args));
      return logger;
    }) as never);
    const errorSpy = jest.spyOn(logger, "error").mockImplementation(((...args: unknown[]) => {
      logMessages.push(JSON.stringify(args));
      return logger;
    }) as never);

    // First attempt -> transient 503 -> retried (pending, cleanupAt remains null)
    jest
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce({
        ok: false,
        status: 503,
        text: async () => JSON.stringify({ message: "Temporary glitch" }),
      } as globalThis.Response)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: "success" }),
      } as globalThis.Response);

    const retrySummary = await processOutboxBatchOnce({
      workerId: "ttl-worker",
      now: new Date(Date.now() + 1000),
    });
    expect(retrySummary.retried).toBe(1);
    const retriedSnap = await EmailOutbox.findOne({ outboxId: issued.outboxId }).lean();
    expect(retriedSnap?.status).toBe("pending");
    expect(retriedSnap?.cleanupAt).toBeNull();
    expect(retriedSnap?.encryptedPayload).toBeTruthy();

    // Second attempt -> sent -> cleanupAt stamped to deliveredAt + 24h & encryptedPayload unset
    const sentSummary = await processOutboxBatchOnce({
      workerId: "ttl-worker",
      now: new Date(Date.now() + 10_000),
    });
    expect(sentSummary.sent).toBe(1);
    const sentSnap = await EmailOutbox.findOne({ outboxId: issued.outboxId }).lean();
    expect(sentSnap?.status).toBe("sent");
    expect(sentSnap?.cleanupAt).toBeInstanceOf(Date);
    expect(sentSnap?.sentAt).toBeInstanceOf(Date);
    expect(
      sentSnap!.cleanupAt!.getTime() - sentSnap!.sentAt!.getTime(),
    ).toBe(24 * 60 * 60 * 1000);
    expect(sentSnap?.encryptedPayload).toBeUndefined();

    // 3. Challenge consumption suppresses still-pending outbox & stamps cleanupAt
    const pendingToSuppress = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: "suppress.on.consume@storra.test",
      ip: "10.6.0.3",
    });
    expect(pendingToSuppress.ok).toBe(true);
    if (!pendingToSuppress.ok) return;
    const preSuppress = await EmailOutbox.findOne({
      outboxId: pendingToSuppress.outboxId,
    }).lean();
    expect(preSuppress?.cleanupAt).toBeNull();
    const suppressOtp = decryptOutboxPayload(preSuppress!.encryptedPayload!).variables.OTP;

    const consumed = await verifyChallengeOtp({
      purpose: "customer_login",
      email: "suppress.on.consume@storra.test",
      challengeId: pendingToSuppress.challengeId,
      otp: suppressOtp,
      ip: "10.6.0.3",
    });
    expect(consumed.ok).toBe(true);

    const postSuppress = await EmailOutbox.findOne({
      outboxId: pendingToSuppress.outboxId,
    }).lean();
    expect(postSuppress?.status).toBe("suppressed");
    expect(postSuppress?.cleanupAt).toBeInstanceOf(Date);
    expect(postSuppress?.encryptedPayload).toBeUndefined();

    // 4. Verify zero logs leaked OTPs or cryptographic keys
    expect(infoSpy.mock.calls.length + warnSpy.mock.calls.length + errorSpy.mock.calls.length).toBeGreaterThan(0);
    for (const entry of logMessages) {
      expect(entry).not.toContain(realOtp);
      expect(entry).not.toContain(suppressOtp);
      expect(entry).not.toContain(env.OUTBOX_ENC_KEY);
      expect(entry).not.toContain(env.OTP_HMAC_SECRET);
      expect(entry).not.toContain(pendingSnap!.encryptedPayload!);
    }
  });
});
