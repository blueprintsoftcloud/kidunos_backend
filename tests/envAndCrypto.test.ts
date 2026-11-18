import crypto from "crypto";
import { env, parseEnv } from "../src/config/env";
import { isPublishedSampleSecret } from "../src/config/secretValidation";
import { generateOtpCode } from "../src/config/mailer";
import { assertOtpCryptoReady } from "../src/utils/otpCrypto";
import {
  MSG91_EMAIL_TIMEOUT_MS,
  hasMsg91EmailConfig,
  sendMsg91TemplateEmail,
} from "../src/config/msg91Email";
import { sendEmail } from "../src/services/email.service";
import { AppSetting } from "../src/models/mongoose";

const STRONG_PROD_HMAC_HEX =
  "e39b1c40f7a82d9e510c4a6b8f2d1e73a90c45b6e2f8170d3c94a58e1b6f02d4";
const STRONG_PROD_ENC_HEX =
  "4f8a21d9c6e03b75194a8d2f60c3b971e5a04d829f1c63b7a05e2d84c91f7630";

const validProdEnvBase = (): Record<string, string> => ({
  NODE_ENV: "production",
  MONGO_URL: "mongodb+srv://user:pass@cluster.example.com/storra",
  JWT_SECRET: "a".repeat(40),
  REFRESH_TOKEN_SECRET: "b".repeat(40),
  OTP_HMAC_SECRET: STRONG_PROD_HMAC_HEX,
  OUTBOX_ENC_KEY: STRONG_PROD_ENC_HEX,
  NOMOD_API_KEY: "test_nomod_api_key",
  RAZORPAY_KEY_ID: "rzp_live_123456",
  RAZORPAY_KEY_SECRET: "rzp_live_secret_654321",
  ALLOWED_ORIGINS: "https://storra.in",
  STOREFRONT_URL: "https://storra.ae",
  TRUST_PROXY_HOPS: "2",
});

describe("PR 1 — Env validation, crypto OTP range, and MSG91 email transport (#13, #15, #16)", () => {
  afterEach(() => {
    jest.restoreAllMocks();
    jest.useRealTimers();
  });

  // Test #13
  describe("env.ts production secret & proxy validation (parseEnv)", () => {
    it("accepts strong distinct production secrets, valid 64-hex OUTBOX_ENC_KEY, and TRUST_PROXY_HOPS", () => {
      const parsed = parseEnv(validProdEnvBase());
      expect(parsed.NODE_ENV).toBe("production");
      expect(parsed.TRUST_PROXY_HOPS).toBe(2);
      expect(parsed.CSRF_SECRET).toBe("");
    });

    it("rejects missing or short JWT_SECRET / REFRESH_TOKEN_SECRET / OTP_HMAC_SECRET / OUTBOX_ENC_KEY in production", () => {
      expect(() => parseEnv({ ...validProdEnvBase(), JWT_SECRET: "short_secret" })).toThrow();
      expect(() =>
        parseEnv({ ...validProdEnvBase(), REFRESH_TOKEN_SECRET: "mysecretkey123_refresh" }),
      ).toThrow();
      expect(() => parseEnv({ ...validProdEnvBase(), REFRESH_TOKEN_SECRET: "short" })).toThrow();
      expect(() => parseEnv({ ...validProdEnvBase(), OTP_HMAC_SECRET: "short" })).toThrow();
      expect(() => parseEnv({ ...validProdEnvBase(), OUTBOX_ENC_KEY: "not-hex-or-short" })).toThrow();
      expect(() => parseEnv({ ...validProdEnvBase(), OUTBOX_ENC_KEY: "z".repeat(64) })).toThrow();
    });

    it("rejects identical JWT_SECRET and REFRESH_TOKEN_SECRET in production", () => {
      const same = "d".repeat(40);
      expect(() =>
        parseEnv({
          ...validProdEnvBase(),
          JWT_SECRET: same,
          REFRESH_TOKEN_SECRET: same,
        }),
      ).toThrow(/must differ from JWT_SECRET/i);
    });

    it("rejects known weak fallback substrings even if padded to 32+ chars", () => {
      expect(() =>
        parseEnv({
          ...validProdEnvBase(),
          JWT_SECRET: "mysecretkey123_padded_to_make_it_longer_than_32",
        }),
      ).toThrow();
    });

    it("requires explicit REFRESH_TOKEN_SECRET even in non-production (no insecure default)", () => {
      const nonProd = { ...validProdEnvBase(), NODE_ENV: "development" };
      delete (nonProd as Record<string, string | undefined>).REFRESH_TOKEN_SECRET;
      expect(() => parseEnv(nonProd)).toThrow();
    });

    it("rejects human-readable 32+ char passphrases and low-entropy hex for production OTP_HMAC_SECRET / OUTBOX_ENC_KEY, while accepting random 256-bit base64 or hex", () => {
      const humanPassphrase32 = "ThisIsA32CharHumanPassphrase1234";
      const humanPassphrase44 = "ThisIsAHumanReadable44CharPassphraseWithoutE";
      const asciiBase64 = Buffer.from("HumanAscii32ByteSecretPassphrase", "utf8").toString("base64");
      const repeatedHex = "c".repeat(64);
      const repeatingChunkHex = "0123456789abcdef".repeat(4);

      for (const weakHmac of [
        humanPassphrase32,
        humanPassphrase44,
        asciiBase64,
        repeatedHex,
        repeatingChunkHex,
        "c".repeat(40),
      ]) {
        let thrownMsg = "";
        try {
          parseEnv({ ...validProdEnvBase(), OTP_HMAC_SECRET: weakHmac });
        } catch (err) {
          thrownMsg = err instanceof Error ? err.message : String(err);
        }
        expect(thrownMsg).toMatch(/OTP_HMAC_SECRET/i);
        // Must never echo secret material in startup error messages
        expect(thrownMsg).not.toContain(weakHmac);
      }

      for (const weakEnc of ["0".repeat(64), "f".repeat(64), repeatingChunkHex]) {
        let thrownMsg = "";
        try {
          parseEnv({ ...validProdEnvBase(), OUTBOX_ENC_KEY: weakEnc });
        } catch (err) {
          thrownMsg = err instanceof Error ? err.message : String(err);
        }
        expect(thrownMsg).toMatch(/OUTBOX_ENC_KEY/i);
        expect(thrownMsg).not.toContain(weakEnc);
      }

      // Accept genuine CSPRNG 256-bit padded base64 (openssl rand -base64 32)
      const randomBase64Key = crypto.randomBytes(32).toString("base64");
      const parsedB64 = parseEnv({
        ...validProdEnvBase(),
        OTP_HMAC_SECRET: randomBase64Key,
      });
      expect(parsedB64.OTP_HMAC_SECRET).toBe(randomBase64Key);
    });

    it("enforces full pairwise key separation across JWT_SECRET, REFRESH_TOKEN_SECRET, OTP_HMAC_SECRET, and OUTBOX_ENC_KEY (including cross-encoding reuse) without echoing values", () => {
      const reusedKey = "91d4f0a872c5e3190b6d2a4f8e1c7356a0d94b72e1f58c0374a69e2b5d0f18c3";
      const reusedBase64 = Buffer.from(reusedKey, "hex").toString("base64");

      const reuseCases: Array<Record<string, string>> = [
        { OTP_HMAC_SECRET: reusedKey, JWT_SECRET: reusedKey },
        { OTP_HMAC_SECRET: reusedKey, REFRESH_TOKEN_SECRET: reusedKey },
        { OUTBOX_ENC_KEY: reusedKey, JWT_SECRET: reusedKey },
        { OUTBOX_ENC_KEY: reusedKey, REFRESH_TOKEN_SECRET: reusedKey },
        { OUTBOX_ENC_KEY: reusedKey, OTP_HMAC_SECRET: reusedKey },
        { OUTBOX_ENC_KEY: reusedKey.toUpperCase(), OTP_HMAC_SECRET: reusedBase64 },
      ];

      for (const overrides of reuseCases) {
        let thrownMsg = "";
        try {
          parseEnv({ ...validProdEnvBase(), ...overrides });
        } catch (err) {
          thrownMsg = err instanceof Error ? err.message : String(err);
        }
        expect(thrownMsg).toMatch(/must differ/i);
        expect(thrownMsg).not.toContain(reusedKey);
        expect(thrownMsg).not.toContain(reusedBase64);
      }

      // Runtime assertOtpCryptoReady() enforces identical strength & pairwise separation
      const origEnv = {
        NODE_ENV: env.NODE_ENV,
        JWT_SECRET: env.JWT_SECRET,
        REFRESH_TOKEN_SECRET: env.REFRESH_TOKEN_SECRET,
        OTP_HMAC_SECRET: env.OTP_HMAC_SECRET,
        OUTBOX_ENC_KEY: env.OUTBOX_ENC_KEY,
      };
      try {
        env.NODE_ENV = "production";
        env.JWT_SECRET = "91d4f0a872c5e3190b6d2a4f8e1c7356a0d94b72e1f58c0374a69e2b5d0f18c3";
        env.REFRESH_TOKEN_SECRET =
          "7a30e1c958b2d4f603a81e7c94f20b65d83c17a9e042f68b51d7c309e482f16a";
        env.OTP_HMAC_SECRET = STRONG_PROD_HMAC_HEX;
        env.OUTBOX_ENC_KEY = STRONG_PROD_ENC_HEX;

        expect(() => assertOtpCryptoReady()).not.toThrow();

        // Human passphrase rejected at crypto initialization in production
        env.OTP_HMAC_SECRET = "ThisIsA32CharHumanPassphrase1234";
        expect(() => assertOtpCryptoReady()).toThrow(/256-bit key/i);

        // Pairwise collision OTP_HMAC_SECRET === JWT_SECRET rejected
        env.OTP_HMAC_SECRET = env.JWT_SECRET;
        expect(() => assertOtpCryptoReady()).toThrow(/must NOT reuse JWT_SECRET/i);
      } finally {
        env.NODE_ENV = origEnv.NODE_ENV;
        env.JWT_SECRET = origEnv.JWT_SECRET;
        env.REFRESH_TOKEN_SECRET = origEnv.REFRESH_TOKEN_SECRET;
        env.OTP_HMAC_SECRET = origEnv.OTP_HMAC_SECRET;
        env.OUTBOX_ENC_KEY = origEnv.OUTBOX_ENC_KEY;
      }
    });

    it("rejects retired .env.example sample cryptographic keys across hex, padded/unpadded Base64, and Base64url encodings for all core secrets without leaking secrets or fingerprints", () => {
      // Retired public sample values previously shown in backend/.env.example (removed cleanly)
      const retiredSample1Hex = [
        "6b1620b0",
        "541ae881",
        "f5ad9d7f",
        "3f1b0677",
        "14266236",
        "78fb6c8a",
        "2b41d379",
        "b0871bb0",
      ].join("");
      const retiredSample2Hex = [
        "03458d5c",
        "00633aef",
        "d3fe6977",
        "10f9c21c",
        "c57d16b3",
        "94f1fc80",
        "dcc98cca",
        "39c63b48",
      ].join("");

      const encodeVariants = (hex: string) => {
        const raw = Buffer.from(hex, "hex");
        const paddedB64 = raw.toString("base64");
        return {
          lowerHex: hex,
          upperHex: hex.toUpperCase(),
          paddedHex: `  ${hex}  `,
          paddedB64,
          unpaddedB64: paddedB64.replace(/=+$/, ""),
          base64url: raw.toString("base64url"),
          sha256Raw: crypto.createHash("sha256").update(raw).digest("hex"),
          sha256Utf8: crypto.createHash("sha256").update(Buffer.from(hex, "utf8")).digest("hex"),
        };
      };

      const s1 = encodeVariants(retiredSample1Hex);
      const s2 = encodeVariants(retiredSample2Hex);

      // 1. Direct detector rejects all encodings of both retired sample keys
      for (const variants of [s1, s2]) {
        for (const candidate of [
          variants.lowerHex,
          variants.upperHex,
          variants.paddedHex,
          variants.paddedB64,
          variants.unpaddedB64,
          variants.base64url,
        ]) {
          expect(isPublishedSampleSecret(candidate)).toBe(true);
        }
      }

      // Fresh CSPRNG 256-bit keys must NOT match
      const freshHex = crypto.randomBytes(32).toString("hex");
      expect(isPublishedSampleSecret(freshHex)).toBe(false);
      expect(isPublishedSampleSecret(Buffer.from(freshHex, "hex").toString("base64"))).toBe(false);
      expect(isPublishedSampleSecret(Buffer.from(freshHex, "hex").toString("base64url"))).toBe(false);

      // 2. Startup env validation rejects every core secret set to a retired sample key in production
      const checkRejected = (
        overrides: Record<string, string>,
        sensitiveValues: string[],
      ) => {
        let thrownMsg = "";
        try {
          parseEnv({ ...validProdEnvBase(), ...overrides });
        } catch (err) {
          thrownMsg = err instanceof Error ? err.message : String(err);
        }
        expect(thrownMsg).toMatch(/published example secret/i);
        for (const sensitive of sensitiveValues) {
          expect(thrownMsg).not.toContain(sensitive);
        }
      };

      for (const v of [s1, s2]) {
        const allSensitive = [
          v.lowerHex,
          v.upperHex,
          v.paddedB64,
          v.unpaddedB64,
          v.base64url,
          v.sha256Raw,
          v.sha256Utf8,
        ];

        for (const otpCandidate of [v.lowerHex, v.upperHex, v.paddedB64]) {
          checkRejected({ OTP_HMAC_SECRET: otpCandidate }, allSensitive);
        }
        for (const encCandidate of [v.lowerHex, v.upperHex]) {
          checkRejected({ OUTBOX_ENC_KEY: encCandidate }, allSensitive);
        }
        for (const authCandidate of [
          v.lowerHex,
          v.upperHex,
          v.paddedB64,
          v.unpaddedB64,
          v.base64url,
        ]) {
          checkRejected({ JWT_SECRET: authCandidate }, allSensitive);
          checkRejected({ REFRESH_TOKEN_SECRET: authCandidate }, allSensitive);
        }
      }

      // 3. Runtime assertOtpCryptoReady() rejects retired sample OTP_HMAC_SECRET & OUTBOX_ENC_KEY in production
      const origEnv = {
        NODE_ENV: env.NODE_ENV,
        JWT_SECRET: env.JWT_SECRET,
        REFRESH_TOKEN_SECRET: env.REFRESH_TOKEN_SECRET,
        OTP_HMAC_SECRET: env.OTP_HMAC_SECRET,
        OUTBOX_ENC_KEY: env.OUTBOX_ENC_KEY,
      };
      try {
        env.NODE_ENV = "production";
        env.JWT_SECRET = crypto.randomBytes(32).toString("hex");
        env.REFRESH_TOKEN_SECRET = crypto.randomBytes(32).toString("hex");
        env.OTP_HMAC_SECRET = STRONG_PROD_HMAC_HEX;
        env.OUTBOX_ENC_KEY = STRONG_PROD_ENC_HEX;
        expect(() => assertOtpCryptoReady()).not.toThrow();

        env.OTP_HMAC_SECRET = s1.paddedB64;
        expect(() => assertOtpCryptoReady()).toThrow(/published example secret/i);

        env.OTP_HMAC_SECRET = STRONG_PROD_HMAC_HEX;
        env.OUTBOX_ENC_KEY = s2.upperHex;
        expect(() => assertOtpCryptoReady()).toThrow(/published example secret/i);

        // Fresh independent 256-bit keys succeed cleanly
        env.OTP_HMAC_SECRET = crypto.randomBytes(32).toString("hex");
        env.OUTBOX_ENC_KEY = crypto.randomBytes(32).toString("hex");
        expect(() => assertOtpCryptoReady()).not.toThrow();
      } finally {
        env.NODE_ENV = origEnv.NODE_ENV;
        env.JWT_SECRET = origEnv.JWT_SECRET;
        env.REFRESH_TOKEN_SECRET = origEnv.REFRESH_TOKEN_SECRET;
        env.OTP_HMAC_SECRET = origEnv.OTP_HMAC_SECRET;
        env.OUTBOX_ENC_KEY = origEnv.OUTBOX_ENC_KEY;
      }
    });
  });

  // Test #15
  describe("mailer.ts generateOtpCode range integrity", () => {
    it("calls crypto.randomInt with exclusive upper bound 1000000 so 999999 is achievable", () => {
      const spy = jest.spyOn(crypto, "randomInt").mockImplementation(() => 999999 as never);
      const code = generateOtpCode();
      expect(spy).toHaveBeenCalledWith(100000, 1000000);
      expect(code).toBe("999999");
    });

    it("produces strictly 6-digit numeric strings within [100000, 999999] across 10,000 samples", () => {
      for (let i = 0; i < 10000; i += 1) {
        const otp = generateOtpCode();
        expect(otp).toMatch(/^\d{6}$/);
        const num = Number(otp);
        expect(num).toBeGreaterThanOrEqual(100000);
        expect(num).toBeLessThanOrEqual(999999);
      }
    });
  });

  // Test #16
  describe("msg91Email.ts & email.service.ts hardened delivery", () => {
    it("targets verified control.msg91.com host with Accept: application/json and authkey", async () => {
      const fetchSpy = jest.spyOn(globalThis, "fetch").mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: "success", message: "queued" }),
      } as globalThis.Response);

      await sendMsg91TemplateEmail({
        to: "staff@storra.test",
        templateId: "tmpl_otp_test",
        variables: { OTP: "123456" },
        throwOnMissingConfig: true,
      });

      expect(fetchSpy).toHaveBeenCalledTimes(1);
      const [url, init] = fetchSpy.mock.calls[0];
      expect(url).toBe("https://control.msg91.com/api/v5/email/send");
      const headers = init?.headers as Record<string, string>;
      expect(headers.Accept).toBe("application/json");
      expect(headers.authkey).toBe(env.MSG91_AUTH_KEY);
    });

    it("throws on non-OK HTTP responses and on HTTP 200 logical JSON error payloads", async () => {
      jest.spyOn(globalThis, "fetch").mockResolvedValueOnce({
        ok: false,
        status: 401,
        text: async () => JSON.stringify({ message: "Unauthorized" }),
      } as globalThis.Response);

      await expect(
        sendMsg91TemplateEmail({
          to: "user@storra.test",
          templateId: "tmpl_otp_test",
          variables: { OTP: "123456" },
        }),
      ).rejects.toThrow(/401/);

      for (const payload of [
        { hasError: true, message: "Invalid template" },
        { status: "fail", errors: ["Bad domain"] },
        { type: "error", message: "Quota exceeded" },
      ]) {
        jest.spyOn(globalThis, "fetch").mockResolvedValueOnce({
          ok: true,
          status: 200,
          text: async () => JSON.stringify(payload),
        } as globalThis.Response);

        await expect(
          sendMsg91TemplateEmail({
            to: "user@storra.test",
            templateId: "tmpl_otp_test",
            variables: { OTP: "123456" },
          }),
        ).rejects.toThrow(/MSG91 email send failed/);
      }
    });

    it("aborts slow MSG91 requests after configured timeout via AbortController", async () => {
      jest.useFakeTimers();

      jest.spyOn(globalThis, "fetch").mockImplementation((_url, init) => {
        return new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            const abortErr = new Error("Aborted");
            abortErr.name = "AbortError";
            reject(abortErr);
          });
        }) as Promise<globalThis.Response>;
      });

      const sendPromise = sendMsg91TemplateEmail({
        to: "user@storra.test",
        templateId: "tmpl_otp_test",
        variables: { OTP: "123456" },
      });

      jest.advanceTimersByTime(MSG91_EMAIL_TIMEOUT_MS + 50);

      await expect(sendPromise).rejects.toThrow(/timed out/i);
    });

    it("throws synchronously when config missing for throwOnMissingConfig=true (OTP), but skips safely for non-OTP", async () => {
      const origDomain = env.MSG91_EMAIL_DOMAIN;
      const findOneSpy = jest.spyOn(AppSetting, "findOne").mockResolvedValue(null as never);
      const fetchSpy = jest.spyOn(globalThis, "fetch");

      try {
        env.MSG91_EMAIL_DOMAIN = "";
        expect(hasMsg91EmailConfig("tmpl_otp_test")).toBe(false);

        await expect(
          sendEmail({
            to: "admin@storra.test",
            templateId: "tmpl_otp_test",
            variables: { OTP: "123456" },
            throwOnMissingConfig: true,
          }),
        ).rejects.toThrow(/incomplete for OTP delivery/i);

        // Non-OTP email remains non-blocking / no-op without crashing caller
        await expect(
          sendEmail({
            to: "customer@storra.test",
            templateId: "tmpl_order_conf_test",
            variables: { ORDER_ID: "ord_1" },
          }),
        ).resolves.toBeUndefined();

        // Give microtask queue a tick to confirm withRetry skipped cleanly without calling fetch
        await new Promise((r) => setTimeout(r, 15));
        expect(fetchSpy).not.toHaveBeenCalled();
        expect(findOneSpy).toHaveBeenCalledTimes(1);
      } finally {
        env.MSG91_EMAIL_DOMAIN = origDomain;
      }
    });
  });
});
