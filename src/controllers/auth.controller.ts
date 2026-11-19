import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import { User, StaffProfile } from "../models/mongoose";
import {
  clearAuthCookies,
  generateToken,
  getAuthCookieOptions,
  hashRefreshTokenValue,
  timingSafeEqualToken,
} from "../config/tokens";
import { env } from "../config/env";
import logger from "../utils/logger";
import {
  hasValidTokenVersionClaim,
  revokeUserSessions,
} from "../services/session.service";
import {
  escapeRegex,
  normalizeEmail,
  normalizeUaeMobile,
  normalizeStrictUaePhone,
} from "../utils/identity";
import { isCustomerEmailOtpEnabled } from "../utils/featureFlags";
import {
  ensureOtpCollectionsInitialized,
  issueChallengeAndEnqueueOutbox,
  resendChallengeAndEnqueueOutbox,
  TxAbortError,
  verifyChallengeOtp,
} from "../services/otp.service";
import {
  signAdminLoginChallengeCookie,
  verifyAdminLoginChallengeCookie,
} from "../utils/otpCrypto";

const ADMIN_CHALLENGE_COOKIE_NAME = "admin_login_challenge";

const clearAdminChallengeCookie = (res: Response): void => {
  res.clearCookie(ADMIN_CHALLENGE_COOKIE_NAME, {
    ...getAuthCookieOptions(),
    path: "/",
  });
};

const isDuplicateKeyError = (err: unknown): boolean => {
  if (typeof err !== "object" || err === null) return false;
  const e = err as { code?: number; cause?: { code?: number } };
  return e.code === 11000 || e.cause?.code === 11000;
};

const extractVerifiedPhoneFromMsg91 = (body: Record<string, unknown>): string | null => {
  const dataObj =
    body.data && typeof body.data === "object"
      ? (body.data as Record<string, unknown>)
      : undefined;

  const candidates: unknown[] = [
    body.mobile,
    body.phone,
    body.identifier,
    dataObj?.mobile,
    dataObj?.phone,
    dataObj?.identifier,
    dataObj?.message,
    body.message,
  ];

  for (const candidate of candidates) {
    const normalized = normalizeUaeMobile(candidate);
    if (normalized) return normalized;
  }
  return null;
};

// POST /api/auth/signup — Permanently retired (legacy unauthenticated password/first-admin path)
export const signup = async (_req: Request, res: Response) => {
  return res.status(410).json({
    message:
      "Legacy public signup has been permanently disabled. Please use the customer registration flow.",
    code: "ENDPOINT_RETIRED",
  });
};

// GET /api/auth/customer/config — Public runtime feature flags for customer auth UX
export const getCustomerAuthConfig = async (_req: Request, res: Response) => {
  res.setHeader("Cache-Control", "no-store");
  const customerEmailOtpEnabled = await isCustomerEmailOtpEnabled();
  return res.status(200).json({
    customerEmailOtpEnabled,
    customerSmsOtpEnabled: true,
  });
};

// POST /api/auth/customer/signup/request-otp (feature-gated PR 2 customer email signup)
export const customerSignupRequestOtp = async (req: Request, res: Response) => {
  try {
    if (!(await isCustomerEmailOtpEnabled())) {
      return res.status(403).json({
        message: "Customer email OTP authentication is not enabled.",
        code: "FEATURE_DISABLED",
      });
    }

    const { name, email, phone } = req.body as {
      name?: unknown;
      email?: unknown;
      phone?: unknown;
    };

    const cleanName = typeof name === "string" ? name.trim() : "";
    if (!cleanName || cleanName.length < 2 || cleanName.length > 80) {
      return res.status(400).json({
        message: "Valid full name (2-80 characters) is required.",
      });
    }

    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail) {
      return res.status(400).json({ message: "Valid email address is required." });
    }

    const submittedPhone = normalizeStrictUaePhone(phone);
    if (!submittedPhone) {
      return res.status(400).json({
        message: "Enter a valid 9-digit UAE mobile number starting with 5.",
      });
    }

    const existing = await User.findOne({
      $or: [
        { phone: submittedPhone },
        { email: normalizedEmail },
        { email: { $regex: `^${escapeRegex(normalizedEmail)}$`, $options: "i" } },
      ],
    })
      .select("_id")
      .lean();

    const isDecoy = Boolean(existing);

    const issued = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_signup",
      email: normalizedEmail,
      toName: cleanName,
      ip: req.ip,
      phone: submittedPhone,
      isDecoy,
      pendingData: {
        name: cleanName,
        email: normalizedEmail,
        phone: submittedPhone,
      },
    });

    if (!issued.ok) {
      return res.status(issued.httpStatus).json({
        message: issued.message,
        code: issued.code,
        ...(issued.retryAfterSeconds ? { retryAfterSeconds: issued.retryAfterSeconds } : {}),
      });
    }

    return res.status(200).json({
      message:
        "If these details are eligible for registration, a 6-digit verification code has been sent to your email.",
      challengeId: issued.challengeId,
      step: "VERIFY_OTP",
      expiresInSeconds: issued.expiresInSeconds,
      resendAfterSeconds: issued.resendAfterSeconds,
    });
  } catch (err: unknown) {
    logger.error("customerSignupRequestOtp error", {
      message: err instanceof Error ? err.message : String(err),
    });
    return res.status(500).json({ message: "Unable to initiate signup verification." });
  }
};

// POST /api/auth/customer/signup/resend-otp (feature-gated PR 2 customer email signup)
export const customerSignupResendOtp = async (req: Request, res: Response) => {
  try {
    if (!(await isCustomerEmailOtpEnabled())) {
      return res.status(403).json({
        message: "Customer email OTP authentication is not enabled.",
        code: "FEATURE_DISABLED",
      });
    }

    const { email, challengeId } = req.body as { email?: unknown; challengeId?: string };
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail || !challengeId) {
      return res
        .status(400)
        .json({ message: "Valid email and verification session are required." });
    }

    const resendRes = await resendChallengeAndEnqueueOutbox({
      purpose: "customer_signup",
      email: normalizedEmail,
      challengeId,
      ip: req.ip,
    });

    if (!resendRes.ok) {
      return res.status(resendRes.httpStatus).json({
        message: resendRes.message,
        code: resendRes.code,
        ...(resendRes.retryAfterSeconds
          ? { retryAfterSeconds: resendRes.retryAfterSeconds }
          : {}),
      });
    }

    return res.status(200).json({
      message:
        "If these details are eligible for registration, a new 6-digit verification code has been sent.",
      challengeId: resendRes.challengeId,
      step: "VERIFY_OTP",
      expiresInSeconds: resendRes.expiresInSeconds,
      resendAfterSeconds: resendRes.resendAfterSeconds,
    });
  } catch (err: unknown) {
    logger.error("customerSignupResendOtp error", {
      message: err instanceof Error ? err.message : String(err),
    });
    return res.status(500).json({ message: "Unable to resend verification code." });
  }
};

// POST /api/auth/customer/signup/verify-otp (feature-gated PR 2 customer email signup)
export const customerSignupVerifyOtp = async (req: Request, res: Response) => {
  try {
    if (!(await isCustomerEmailOtpEnabled())) {
      return res.status(403).json({
        message: "Customer email OTP authentication is not enabled.",
        code: "FEATURE_DISABLED",
      });
    }

    const { email, challengeId, otp } = req.body as {
      email?: unknown;
      challengeId?: string;
      otp?: string;
    };

    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail || !challengeId || !otp) {
      return res
        .status(400)
        .json({ message: "Email, verification session, and 6-digit code are required." });
    }

    await ensureOtpCollectionsInitialized();

    const session = await mongoose.startSession();
    let createdUser: { id: string; username: string; email: string; role: string } | null = null;
    let failureResponse: {
      httpStatus: number;
      code: string;
      message: string;
      attemptsRemaining?: number;
      retryAfterSeconds?: number;
    } | null = null;

    try {
      await session.withTransaction(async () => {
        createdUser = null;
        failureResponse = null;

        const verifyRes = await verifyChallengeOtp({
          purpose: "customer_signup",
          email: normalizedEmail,
          otp,
          challengeId,
          ip: req.ip,
          session,
        });

        if (!verifyRes.ok) {
          failureResponse = {
            httpStatus: verifyRes.httpStatus,
            code: verifyRes.code,
            message: verifyRes.message,
            attemptsRemaining: verifyRes.attemptsRemaining,
            retryAfterSeconds: verifyRes.retryAfterSeconds,
          };
          throw new TxAbortError();
        }

        const pending = (verifyRes.challenge.pendingData ?? {}) as {
          name?: unknown;
          email?: unknown;
          phone?: unknown;
        };

        const cleanName = typeof pending.name === "string" ? pending.name.trim() : "";
        const pendingEmail = normalizeEmail(pending.email);
        const pendingPhone = normalizeStrictUaePhone(pending.phone);

        if (
          !cleanName ||
          !pendingEmail ||
          pendingEmail !== normalizedEmail ||
          !pendingPhone
        ) {
          failureResponse = {
            httpStatus: 400,
            code: "CHALLENGE_INVALID",
            message: "Verification session payload is invalid. Please sign up again.",
          };
          throw new TxAbortError();
        }

        const existingConflict = await User.findOne({
          $or: [
            { phone: pendingPhone },
            { email: pendingEmail },
            { email: { $regex: `^${escapeRegex(pendingEmail)}$`, $options: "i" } },
          ],
        })
          .select("_id")
          .session(session)
          .lean();

        if (existingConflict) {
          failureResponse = {
            httpStatus: 409,
            code: "SIGNUP_CONFLICT",
            message:
              "Unable to complete registration with these details. Please sign in or use different details.",
          };
          throw new TxAbortError();
        }

        const newUser = new User({
          username: cleanName,
          email: pendingEmail,
          phone: pendingPhone,
          role: "CUSTOMER",
          isVerified: true,
          emailVerifiedAt: new Date(),
          isActive: true,
          tokenVersion: 0,
          posActivationRequired: false,
        });

        await newUser.save({ session });
        createdUser = {
          id: newUser.id,
          username: newUser.username,
          email: pendingEmail,
          role: newUser.role,
        };
      });
    } catch (txErr: unknown) {
      if (!(txErr instanceof TxAbortError)) {
        if (isDuplicateKeyError(txErr)) {
          return res.status(409).json({
            message:
              "Unable to complete registration with these details. Please sign in or use different details.",
            code: "SIGNUP_CONFLICT",
          });
        }
        throw txErr;
      }
    } finally {
      await session.endSession();
    }

    if (failureResponse) {
      const f = failureResponse as {
        httpStatus: number;
        code: string;
        message: string;
        attemptsRemaining?: number;
        retryAfterSeconds?: number;
      };
      return res.status(f.httpStatus).json({
        message: f.message,
        code: f.code,
        ...(typeof f.attemptsRemaining === "number"
          ? { attemptsRemaining: f.attemptsRemaining }
          : {}),
        ...(f.retryAfterSeconds ? { retryAfterSeconds: f.retryAfterSeconds } : {}),
      });
    }

    if (!createdUser) {
      return res.status(500).json({ message: "Unable to complete registration." });
    }

    const userSummary = createdUser as {
      id: string;
      username: string;
      email: string;
      role: string;
    };

    await generateToken(
      {
        id: userSummary.id,
        email: userSummary.email,
        role: userSummary.role,
        tokenVersion: 0,
      },
      res,
    );

    logger.info("customerSignupVerifyOtp: created customer account", {
      id: userSummary.id,
    });
    return res.status(201).json({
      message: "Account created successfully. Welcome!",
      user: {
        id: userSummary.id,
        username: userSummary.username,
        role: userSummary.role,
      },
    });
  } catch (err: unknown) {
    logger.error("customerSignupVerifyOtp error", {
      message: err instanceof Error ? err.message : String(err),
    });
    return res.status(500).json({ message: "Error verifying signup code." });
  }
};

// POST /api/auth/customer/login/request-otp (feature-gated PR 2 customer email login)
export const customerLoginRequestOtp = async (req: Request, res: Response) => {
  try {
    if (!(await isCustomerEmailOtpEnabled())) {
      return res.status(403).json({
        message: "Customer email OTP authentication is not enabled.",
        code: "FEATURE_DISABLED",
      });
    }

    const normalizedEmail = normalizeEmail(req.body?.email);
    if (!normalizedEmail) {
      return res.status(400).json({ message: "Valid email address is required." });
    }

    const users = await User.find({
      $or: [
        { email: normalizedEmail },
        { email: { $regex: `^${escapeRegex(normalizedEmail)}$`, $options: "i" } },
      ],
    })
      .select("_id username email role isActive emailVerifiedAt posActivationRequired")
      .lean();

    if (users.length === 0) {
      return res.status(404).json({
        message: "No customer account was found for this email. Please create an account.",
        code: "CUSTOMER_NOT_FOUND",
      });
    }

    if (users.some((account) => account.role !== "CUSTOMER")) {
      return res.status(403).json({
        message: "This email cannot be used to sign in through the customer login.",
        code: "ROLE_RESTRICTED",
      });
    }

    const user = users[0];
    if (user.isActive === false) {
      return res.status(403).json({
        message: "Your account has been deactivated. Please contact support.",
        code: "ACCOUNT_DEACTIVATED",
      });
    }

    if (!user.emailVerifiedAt || user.posActivationRequired) {
      return res.status(403).json({
        message: "Email verification is required before signing in via Email OTP.",
        code: "EMAIL_NOT_VERIFIED",
      });
    }

    const issued = await issueChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: normalizedEmail,
      toName: user.username,
      ip: req.ip,
      userId: user._id,
    });

    if (!issued.ok) {
      return res.status(issued.httpStatus).json({
        message: issued.message,
        code: issued.code,
        ...(issued.retryAfterSeconds ? { retryAfterSeconds: issued.retryAfterSeconds } : {}),
      });
    }

    return res.status(200).json({
      message: "A 6-digit verification code has been sent to your email.",
      challengeId: issued.challengeId,
      step: "VERIFY_OTP",
      expiresInSeconds: issued.expiresInSeconds,
      resendAfterSeconds: issued.resendAfterSeconds,
    });
  } catch (err: unknown) {
    logger.error("customerLoginRequestOtp error", {
      message: err instanceof Error ? err.message : String(err),
    });
    return res.status(500).json({ message: "Unable to initiate login verification." });
  }
};

// POST /api/auth/customer/login/resend-otp (feature-gated PR 2 customer email login)
export const customerLoginResendOtp = async (req: Request, res: Response) => {
  try {
    if (!(await isCustomerEmailOtpEnabled())) {
      return res.status(403).json({
        message: "Customer email OTP authentication is not enabled.",
        code: "FEATURE_DISABLED",
      });
    }

    const { email, challengeId } = req.body as { email?: unknown; challengeId?: string };
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail || !challengeId) {
      return res
        .status(400)
        .json({ message: "Valid email and verification session are required." });
    }

    const resendRes = await resendChallengeAndEnqueueOutbox({
      purpose: "customer_login",
      email: normalizedEmail,
      challengeId,
      ip: req.ip,
    });

    if (!resendRes.ok) {
      return res.status(resendRes.httpStatus).json({
        message: resendRes.message,
        code: resendRes.code,
        ...(resendRes.retryAfterSeconds
          ? { retryAfterSeconds: resendRes.retryAfterSeconds }
          : {}),
      });
    }

    return res.status(200).json({
      message:
        "If an eligible customer account exists for this email, a new 6-digit verification code has been sent.",
      challengeId: resendRes.challengeId,
      step: "VERIFY_OTP",
      expiresInSeconds: resendRes.expiresInSeconds,
      resendAfterSeconds: resendRes.resendAfterSeconds,
    });
  } catch (err: unknown) {
    logger.error("customerLoginResendOtp error", {
      message: err instanceof Error ? err.message : String(err),
    });
    return res.status(500).json({ message: "Unable to resend verification code." });
  }
};

// POST /api/auth/customer/login/verify-otp (feature-gated PR 2 customer email login)
export const customerLoginVerifyOtp = async (req: Request, res: Response) => {
  try {
    if (!(await isCustomerEmailOtpEnabled())) {
      return res.status(403).json({
        message: "Customer email OTP authentication is not enabled.",
        code: "FEATURE_DISABLED",
      });
    }

    const { email, challengeId, otp } = req.body as {
      email?: unknown;
      challengeId?: string;
      otp?: string;
    };
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail || !challengeId || !otp) {
      return res
        .status(400)
        .json({ message: "Email, verification session, and 6-digit code are required." });
    }

    const verifyRes = await verifyChallengeOtp({
      purpose: "customer_login",
      email: normalizedEmail,
      otp,
      challengeId,
      ip: req.ip,
    });

    if (!verifyRes.ok) {
      return res.status(verifyRes.httpStatus).json({
        message: verifyRes.message,
        code: verifyRes.code,
        ...(typeof verifyRes.attemptsRemaining === "number"
          ? { attemptsRemaining: verifyRes.attemptsRemaining }
          : {}),
        ...(verifyRes.retryAfterSeconds
          ? { retryAfterSeconds: verifyRes.retryAfterSeconds }
          : {}),
      });
    }

    const boundUserId = verifyRes.challenge.userId;
    if (!boundUserId) {
      return res.status(401).json({
        message: "Verification session is not bound to an account.",
        code: "CHALLENGE_INVALID",
      });
    }

    const user = await User.findById(boundUserId);
    if (!user || normalizeEmail(user.email) !== normalizedEmail) {
      return res.status(401).json({
        message: "Account state changed. Please request a new login code.",
        code: "CHALLENGE_INVALID",
      });
    }

    if (user.role !== "CUSTOMER") {
      return res.status(403).json({
        message: "This account cannot sign in via customer email login.",
        code: "ROLE_RESTRICTED",
      });
    }

    if (user.isActive === false) {
      return res.status(403).json({
        message: "Your account has been deactivated. Please contact support.",
        code: "ACCOUNT_DEACTIVATED",
      });
    }

    if (!user.emailVerifiedAt || user.posActivationRequired) {
      return res.status(403).json({
        message: "Email verification is required before signing in via Email OTP.",
        code: "EMAIL_NOT_VERIFIED",
      });
    }

    await generateToken(
      {
        id: user.id,
        email: normalizedEmail,
        role: user.role,
        tokenVersion: user.tokenVersion ?? 0,
      },
      res,
    );

    return res.status(200).json({
      message: "Login successful.",
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (err: unknown) {
    logger.error("customerLoginVerifyOtp error", {
      message: err instanceof Error ? err.message : String(err),
    });
    return res.status(500).json({ message: "Server error during login verification." });
  }
};

// POST /api/auth/login — Step 1: validate staff/admin credentials, issue challenge + EmailOutbox
export const login = async (req: Request, res: Response) => {
  try {
    const { password } = req.body as { password?: string };
    const email = normalizeEmail(req.body?.email);
    if (!email) return res.status(400).json({ message: "Email is required" });

    const user = await User.findOne({
      $or: [
        { email },
        { email: { $regex: `^${escapeRegex(email)}$`, $options: "i" } },
      ],
    });
    if (!user) {
      return res.status(400).json({ message: "No account registered with this email" });
    }

    // Legacy CUSTOMER password hashes remain untouched in MongoDB but are unreachable via password login.
    if (user.role === "CUSTOMER") {
      return res.status(403).json({
        message: "Customer accounts cannot sign in through staff/admin password login.",
        code: "ROLE_RESTRICTED",
      });
    }

    if (user.isActive === false) {
      return res.status(403).json({
        message: "Your account has been deactivated. Please contact your administrator.",
      });
    }

    if (!user.password) {
      return res.status(400).json({
        message: "Password login is not enabled for this account.",
      });
    }

    const isMatch = await bcrypt.compare(password ?? "", user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Password is incorrect" });
    }

    if (user.role === "STAFF") {
      const staffProfile = await StaffProfile.findOne({ userId: user._id }).lean();
      if (!staffProfile || staffProfile.isActive === false) {
        return res.status(403).json({
          message: "Your account has been deactivated. Please contact your administrator for access.",
        });
      }
    }

    const tokenVersionSnapshot = typeof user.tokenVersion === "number" ? user.tokenVersion : 0;
    const issued = await issueChallengeAndEnqueueOutbox({
      purpose: "admin_login",
      email,
      toName: user.username,
      ip: req.ip,
      authVerified: true,
      userId: user._id,
      tokenVersionSnapshot,
    });

    if (!issued.ok) {
      return res.status(issued.httpStatus).json({
        message: issued.message,
        code: issued.code,
        ...(issued.retryAfterSeconds ? { retryAfterSeconds: issued.retryAfterSeconds } : {}),
      });
    }

    const cookieToken = signAdminLoginChallengeCookie({
      challengeId: issued.challengeId,
      userId: user.id,
      email,
      tokenVersionSnapshot,
    });

    res.cookie(ADMIN_CHALLENGE_COOKIE_NAME, cookieToken, {
      maxAge: 15 * 60 * 1000,
      ...getAuthCookieOptions(),
      path: "/",
    });

    return res.status(200).json({
      message: "Credentials verified. OTP sent to your email.",
      step: "VERIFY_OTP",
      email,
      challengeId: issued.challengeId,
      expiresInSeconds: issued.expiresInSeconds,
      resendAfterSeconds: issued.resendAfterSeconds,
    });
  } catch (err: unknown) {
    logger.error("login error", err);
    return res.status(500).json({
      error: "Error occurred",
      message: err instanceof Error ? err.message : "Server error",
    });
  }
};

// POST /api/auth/login/verify — Step 2: verify challenge cookie + OTP, issue versioned tokens
export const verifyLoginOtp = async (req: Request, res: Response) => {
  try {
    const { otp, challengeId: bodyChallengeId } = req.body as {
      otp?: string;
      challengeId?: string;
    };
    const email = normalizeEmail(req.body?.email);
    if (!email) {
      return res.status(400).json({ message: "Valid email is required." });
    }

    const challengeClaims = verifyAdminLoginChallengeCookie(
      req.cookies?.[ADMIN_CHALLENGE_COOKIE_NAME],
    );
    if (!challengeClaims) {
      clearAdminChallengeCookie(res);
      return res.status(401).json({
        message: "Pre-authentication challenge session is missing or expired. Please log in again.",
        code: "CHALLENGE_MISSING",
      });
    }

    if (challengeClaims.email !== email) {
      return res.status(401).json({
        message: "Verification session does not match the submitted email.",
        code: "CHALLENGE_INVALID",
      });
    }

    if (bodyChallengeId && bodyChallengeId !== challengeClaims.challengeId) {
      return res.status(401).json({
        message: "Verification session mismatch. Please log in again.",
        code: "CHALLENGE_INVALID",
      });
    }

    const user = await User.findById(challengeClaims.userId);
    if (!user || normalizeEmail(user.email) !== email) {
      clearAdminChallengeCookie(res);
      return res.status(401).json({
        message: "Account state changed. Please log in again.",
        code: "CHALLENGE_INVALID",
      });
    }

    if (user.role === "CUSTOMER") {
      clearAdminChallengeCookie(res);
      return res.status(403).json({
        message: "Customer accounts cannot sign in through staff/admin password login.",
        code: "ROLE_RESTRICTED",
      });
    }

    if (user.isActive === false) {
      clearAdminChallengeCookie(res);
      return res.status(403).json({
        message: "Your account has been deactivated. Please contact your administrator.",
        code: "ACCOUNT_DEACTIVATED",
      });
    }

    if (user.role === "STAFF") {
      const staffProfile = await StaffProfile.findOne({ userId: user._id }).lean();
      if (!staffProfile || staffProfile.isActive === false) {
        clearAdminChallengeCookie(res);
        return res.status(403).json({
          message: "Your account has been deactivated. Please contact your administrator.",
          code: "ACCOUNT_DEACTIVATED",
        });
      }
    }

    const dbTokenVersion = typeof user.tokenVersion === "number" ? user.tokenVersion : 0;
    if (dbTokenVersion !== challengeClaims.tokenVersionSnapshot) {
      clearAdminChallengeCookie(res);
      return res.status(401).json({
        message: "Your session state changed. Please log in again.",
        code: "TOKEN_VERSION_MISMATCH",
      });
    }

    const verifyRes = await verifyChallengeOtp({
      purpose: "admin_login",
      email,
      otp: otp ?? "",
      challengeId: challengeClaims.challengeId,
      userId: user._id,
      requireAuthVerified: true,
      expectedTokenVersion: dbTokenVersion,
      ip: req.ip,
    });

    if (!verifyRes.ok) {
      if (
        verifyRes.code === "CHALLENGE_LOCKED" ||
        verifyRes.code === "CHALLENGE_CONSUMED" ||
        verifyRes.code === "CHALLENGE_EXPIRED" ||
        verifyRes.code === "CHALLENGE_INVALID" ||
        verifyRes.code === "TOKEN_VERSION_MISMATCH" ||
        verifyRes.code === "AUTH_NOT_VERIFIED"
      ) {
        clearAdminChallengeCookie(res);
      }
      return res.status(verifyRes.httpStatus).json({
        message: verifyRes.message,
        code: verifyRes.code,
        ...(typeof verifyRes.attemptsRemaining === "number"
          ? { attemptsRemaining: verifyRes.attemptsRemaining }
          : {}),
        ...(verifyRes.retryAfterSeconds
          ? { retryAfterSeconds: verifyRes.retryAfterSeconds }
          : {}),
      });
    }

    // Immediate pre-issuance recheck before minting auth cookies
    const freshUser = await User.findById(user._id).lean();
    if (
      !freshUser ||
      freshUser.role === "CUSTOMER" ||
      freshUser.isActive === false ||
      (freshUser.tokenVersion ?? 0) !== challengeClaims.tokenVersionSnapshot
    ) {
      clearAdminChallengeCookie(res);
      return res.status(403).json({
        message: "Account access could not be verified. Please log in again.",
        code: "ACCOUNT_DEACTIVATED",
      });
    }

    if (freshUser.role === "STAFF") {
      const freshStaffProfile = await StaffProfile.findOne({ userId: freshUser._id }).lean();
      if (!freshStaffProfile || freshStaffProfile.isActive === false) {
        clearAdminChallengeCookie(res);
        return res.status(403).json({
          message: "Your account has been deactivated. Please contact your administrator.",
          code: "ACCOUNT_DEACTIVATED",
        });
      }
    }

    clearAdminChallengeCookie(res);

    await generateToken(
      {
        id: String(freshUser._id),
        email,
        role: freshUser.role,
        tokenVersion: freshUser.tokenVersion ?? 0,
      },
      res,
    );

    return res.status(200).json({
      message: "Logged in successfully",
      role: freshUser.role,
    });
  } catch (err: unknown) {
    logger.error("verifyLoginOtp error", err);
    return res
      .status(500)
      .json({ message: "Server error during verification." });
  }
};

// POST /api/auth/resend-otp — requires valid pre-authenticated admin_login_challenge cookie
export const resendOtp = async (req: Request, res: Response) => {
  try {
    const email = normalizeEmail(req.body?.email);
    if (!email) return res.status(400).json({ message: "Email is required" });

    const challengeClaims = verifyAdminLoginChallengeCookie(
      req.cookies?.[ADMIN_CHALLENGE_COOKIE_NAME],
    );
    if (!challengeClaims) {
      clearAdminChallengeCookie(res);
      return res.status(401).json({
        message:
          "Active pre-authentication challenge is required before resending OTP. Please log in again.",
        code: "CHALLENGE_MISSING",
      });
    }

    if (challengeClaims.email !== email) {
      return res.status(401).json({
        message: "Login challenge does not match this email.",
        code: "CHALLENGE_INVALID",
      });
    }

    if (req.body?.challengeId && req.body.challengeId !== challengeClaims.challengeId) {
      return res.status(401).json({
        message: "Verification session mismatch.",
        code: "CHALLENGE_INVALID",
      });
    }

    const user = await User.findById(challengeClaims.userId).lean();
    if (!user || normalizeEmail(user.email) !== email || user.role === "CUSTOMER" || user.isActive === false) {
      clearAdminChallengeCookie(res);
      return res.status(403).json({
        message: "Account access is unavailable.",
        code: "ACCOUNT_DEACTIVATED",
      });
    }

    if (user.role === "STAFF") {
      const staffProfile = await StaffProfile.findOne({ userId: user._id }).lean();
      if (!staffProfile || staffProfile.isActive === false) {
        clearAdminChallengeCookie(res);
        return res.status(403).json({
          message: "Your account has been deactivated. Please contact your administrator.",
          code: "ACCOUNT_DEACTIVATED",
        });
      }
    }

    const dbTokenVersion = typeof user.tokenVersion === "number" ? user.tokenVersion : 0;
    if (dbTokenVersion !== challengeClaims.tokenVersionSnapshot) {
      clearAdminChallengeCookie(res);
      return res.status(401).json({
        message: "Session state changed. Please log in again.",
        code: "TOKEN_VERSION_MISMATCH",
      });
    }

    const resendRes = await resendChallengeAndEnqueueOutbox({
      purpose: "admin_login",
      email,
      challengeId: challengeClaims.challengeId,
      userId: user._id,
      requireAuthVerified: true,
      expectedTokenVersion: dbTokenVersion,
      ip: req.ip,
      toName: user.username,
    });

    if (!resendRes.ok) {
      if (
        resendRes.code === "CHALLENGE_LOCKED" ||
        resendRes.code === "CHALLENGE_CONSUMED" ||
        resendRes.code === "CHALLENGE_EXPIRED" ||
        resendRes.code === "CHALLENGE_INVALID" ||
        resendRes.code === "MAX_RESENDS_EXCEEDED"
      ) {
        clearAdminChallengeCookie(res);
      }
      return res.status(resendRes.httpStatus).json({
        message: resendRes.message,
        code: resendRes.code,
        ...(resendRes.retryAfterSeconds
          ? { retryAfterSeconds: resendRes.retryAfterSeconds }
          : {}),
      });
    }

    const rotatedChallengeCookie = signAdminLoginChallengeCookie({
      challengeId: resendRes.challengeId,
      userId: String(user._id),
      email,
      tokenVersionSnapshot: dbTokenVersion,
    });

    res.cookie(ADMIN_CHALLENGE_COOKIE_NAME, rotatedChallengeCookie, {
      maxAge: 15 * 60 * 1000,
      ...getAuthCookieOptions(),
      path: "/",
    });

    return res.status(200).json({
      message: "New verification code sent to your email.",
      email,
      challengeId: resendRes.challengeId,
      expiresInSeconds: resendRes.expiresInSeconds,
      resendAfterSeconds: resendRes.resendAfterSeconds,
    });
  } catch (err: unknown) {
    logger.error("resendOtp error", err);
    return res.status(500).json({
      error: "Error occurred during resend",
      details: err instanceof Error ? err.message : String(err),
    });
  }
};

// POST /api/auth/logout
export const logout = async (req: Request, res: Response) => {
  clearAuthCookies(res);
  clearAdminChallengeCookie(res);

  try {
    // Only trust cryptographically verified JWT signatures (even when expired) so an
    // unauthenticated attacker cannot force-increment tokenVersion for an arbitrary userId.
    let userId: string | undefined = req.user?.id;

    if (!userId) {
      const token = req.cookies?.jwt as string | undefined;
      if (token) {
        try {
          const verified = jwt.verify(token, env.JWT_SECRET, {
            ignoreExpiration: true,
          }) as { id?: string };
          if (typeof verified?.id === "string") userId = verified.id;
        } catch {
          // Tampered/unverified JWT ignored
        }
      }
    }

    if (!userId) {
      const refreshToken = req.cookies?.refreshToken as string | undefined;
      if (refreshToken) {
        try {
          const verified = jwt.verify(refreshToken, env.REFRESH_TOKEN_SECRET, {
            ignoreExpiration: true,
          }) as { id?: string };
          if (typeof verified?.id === "string") userId = verified.id;
        } catch {
          // Tampered/unverified refreshToken ignored
        }
      }
    }

    if (userId) {
      await revokeUserSessions(req.app.get("socketio"), userId, "LOGOUT");
    }

    return res.status(200).json({ message: "Logout Successful" });
  } catch (err: unknown) {
    logger.error("logout error", err);
    return res.status(200).json({ message: "Logout Successful" });
  }
};

// POST /api/auth/refresh
export const refreshTokens = async (req: Request, res: Response) => {
  const refreshToken = req.cookies?.refreshToken as string | undefined;
  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token not provided." });
  }

  try {
    const decoded = jwt.verify(refreshToken, env.REFRESH_TOKEN_SECRET) as {
      id?: string;
      tokenValue?: string;
      family?: string;
      tokenVersion?: unknown;
    };

    if (
      typeof decoded.id !== "string" ||
      typeof decoded.tokenValue !== "string" ||
      !decoded.tokenValue ||
      typeof decoded.family !== "string" ||
      !decoded.family
    ) {
      clearAuthCookies(res);
      return res.status(401).json({ message: "Invalid refresh token payload." });
    }

    if (!hasValidTokenVersionClaim(decoded.tokenVersion)) {
      clearAuthCookies(res);
      return res.status(401).json({
        message: "Session security upgrade requires re-authentication. Please log in again.",
        code: "LEGACY_TOKEN",
      });
    }

    const user = await User.findById(decoded.id);
    if (!user) {
      clearAuthCookies(res);
      return res.status(403).json({ message: "Invalid or revoked refresh token." });
    }

    if (user.isActive === false) {
      clearAuthCookies(res);
      return res.status(403).json({
        message: "Your account has been deactivated. Please contact support.",
      });
    }

    const dbTokenVersion = typeof user.tokenVersion === "number" ? user.tokenVersion : 0;
    if (decoded.tokenVersion !== dbTokenVersion) {
      clearAuthCookies(res);
      return res.status(403).json({
        message: "Your session has been revoked. Please log in again.",
        code: "TOKEN_VERSION_MISMATCH",
      });
    }

    const now = Date.now();
    const GRACE_WINDOW_MS = 15 * 60 * 1000;
    const submittedDigest = hashRefreshTokenValue(decoded.tokenValue);
    const isSameFamily = Boolean(user.refreshTokenFamily) && user.refreshTokenFamily === decoded.family;

    const isCurrentToken =
      isSameFamily &&
      Boolean(user.refreshToken) &&
      timingSafeEqualToken(user.refreshToken!, submittedDigest);

    const recentTokens = user.previousRefreshTokens || [];
    const isInRecentTokens =
      isSameFamily &&
      recentTokens.some(
        (item) =>
          item.token &&
          timingSafeEqualToken(item.token, submittedDigest) &&
          now - new Date(item.rotatedAt).getTime() < GRACE_WINDOW_MS,
      );

    const isLegacyGraceToken =
      isSameFamily &&
      !!user.previousRefreshToken &&
      timingSafeEqualToken(user.previousRefreshToken, submittedDigest) &&
      !!user.lastRotatedAt &&
      now - new Date(user.lastRotatedAt).getTime() < GRACE_WINDOW_MS;

    const isGracePeriodToken = isInRecentTokens || isLegacyGraceToken;

    if (!isCurrentToken && !isGracePeriodToken) {
      logger.warn("Refresh token invalid or expired outside grace period", {
        userId: user.id,
        family: decoded.family,
        ip: req.ip,
      });
      clearAuthCookies(res);
      return res.status(403).json({
        message: "Invalid or expired session. Please log in again.",
      });
    }

    if (user.role === "STAFF") {
      const staffProfile = await StaffProfile.findOne({ userId: user._id }).lean();
      if (!staffProfile || staffProfile.isActive === false) {
        clearAuthCookies(res);
        logger.warn("Refresh blocked: Deactivated staff member attempted token refresh", {
          userId: user._id,
        });
        return res.status(403).json({
          message: "Your account has been deactivated. Please contact your administrator.",
        });
      }
    }

    await generateToken(
      {
        id: user.id,
        email: user.email ?? "",
        role: user.role,
        tokenVersion: dbTokenVersion,
      },
      res,
      decoded.family,
    );

    return res.status(200).json({
      message: "Access token refreshed successfully.",
      isLoggedIn: true,
      role: user.role,
    });
  } catch {
    clearAuthCookies(res);
    return res.status(403).json({
      message: "Invalid or expired refresh token. Please log in again.",
    });
  }
};

// ─── MSG91 Mobile OTP (Hardened Prep Window) ───────────────────────────────────

/** Verify a MSG91 widget access token server-side and extract its canonical verified phone. */
export const verifyMsg91Token = async (
  accessToken: string,
): Promise<{
  ok: boolean;
  status?: number;
  verifiedPhone?: string | null;
  body?: Record<string, unknown>;
}> => {
  if (!env.MSG91_AUTH_KEY) {
    logger.error("verifyMsg91Token: MSG91_AUTH_KEY is not configured");
    return { ok: false, status: 500, verifiedPhone: null };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 12000);
  try {
    const resp = await fetch(
      "https://control.msg91.com/api/v5/widget/verifyAccessToken",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ authkey: env.MSG91_AUTH_KEY, "access-token": accessToken }),
        signal: controller.signal,
      },
    );
    clearTimeout(timeoutId);
    const rawText = await resp.text();
    let body: Record<string, unknown> = {};
    try {
      body = rawText ? (JSON.parse(rawText) as Record<string, unknown>) : {};
    } catch {
      body = { raw: rawText };
    }

    const typeSuccess = typeof body.type === "string" && body.type.toLowerCase() === "success";
    const verifiedPhone = extractVerifiedPhoneFromMsg91(body);

    if (!resp.ok || !typeSuccess) {
      return { ok: false, status: resp.status, verifiedPhone: null, body };
    }

    // Fail closed if MSG91 returned success without a verifiable mobile identifier.
    if (!verifiedPhone) {
      logger.warn("verifyMsg91Token: MSG91 response missing verifiable mobile identifier", {
        status: resp.status,
      });
      return { ok: false, status: 401, verifiedPhone: null, body };
    }

    return { ok: true, status: resp.status, verifiedPhone, body };
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    const e = err as Error;
    if (e?.name === "AbortError" || controller.signal.aborted) {
      logger.error("verifyMsg91Token: timeout verifying token with MSG91 gateway");
      return {
        ok: false,
        status: 504,
        verifiedPhone: null,
        body: { message: "MSG91 verification gateway timeout" },
      };
    }
    throw err;
  }
};

// POST /api/auth/mobile/login
export const mobileLogin = async (req: Request, res: Response) => {
  const { phone, accessToken } = req.body as { phone: string; accessToken: string };
  const submittedPhone = normalizeUaeMobile(phone);
  if (!submittedPhone) {
    return res.status(400).json({ message: "Invalid mobile number format." });
  }

  try {
    let result: Awaited<ReturnType<typeof verifyMsg91Token>>;
    try {
      result = await verifyMsg91Token(accessToken);
    } catch (fetchErr) {
      const e = fetchErr as Error;
      logger.error("mobileLogin verifyMsg91Token threw", { message: e?.message });
      return res.status(502).json({ message: "Could not verify OTP token. Please try again." });
    }

    if (!result.ok || !result.verifiedPhone) {
      logger.warn("mobileLogin: MSG91 rejected token", { status: result.status });
      return res.status(result.status === 504 ? 504 : 401).json({
        message: "OTP verification failed. Please try again.",
      });
    }

    // Bind MSG91's verified phone number to req.body.phone.
    if (!timingSafeEqualToken(result.verifiedPhone, submittedPhone)) {
      logger.warn("mobileLogin: MSG91 token identifier mismatch against submitted phone", {
        ip: req.ip,
      });
      return res.status(403).json({
        message: "Verified mobile number does not match the submitted phone number.",
        code: "PHONE_MISMATCH",
      });
    }

    const user = await User.findOne({ phone: submittedPhone });
    if (!user) {
      return res.status(404).json({
        message: "No account found with this number. Please sign up first.",
        code: "NO_ACCOUNT",
      });
    }

    if (user.role !== "CUSTOMER") {
      logger.warn("mobileLogin: privileged/staff role blocked from customer SMS login", {
        userId: user.id,
        role: user.role,
      });
      return res.status(403).json({
        message: "This account cannot be accessed via customer SMS login. Please use the Staff/Admin portal.",
        code: "ROLE_RESTRICTED",
      });
    }

    if (user.isActive === false) {
      return res.status(403).json({
        message: "Your account has been deactivated. Please contact support.",
        code: "ACCOUNT_DEACTIVATED",
      });
    }

    await generateToken(
      {
        id: user.id,
        email: user.email ?? "",
        role: user.role,
        tokenVersion: user.tokenVersion ?? 0,
      },
      res,
    );

    return res.status(200).json({
      message: "Login successful.",
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (err: unknown) {
    const e = err as Error;
    logger.error("mobileLogin error", { message: e?.message, stack: e?.stack });
    return res.status(500).json({ message: "Server error." });
  }
};

// POST /api/auth/mobile/register
export const registerCustomer = async (req: Request, res: Response) => {
  const { name, email, phone, accessToken } = req.body as {
    name?: unknown;
    email?: unknown;
    phone?: unknown;
    accessToken?: unknown;
  };

  // Defense-in-depth backend re-validation of mandatory signup identity fields
  const cleanName = typeof name === "string" ? name.trim() : "";
  if (!cleanName || cleanName.length < 2 || cleanName.length > 80) {
    return res.status(400).json({ message: "Valid full name (2-80 characters) is required." });
  }

  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) {
    return res.status(400).json({ message: "Valid email address is required." });
  }

  const submittedPhone = normalizeStrictUaePhone(phone);
  if (!submittedPhone) {
    return res.status(400).json({ message: "Invalid mobile number format." });
  }

  const cleanAccessToken = typeof accessToken === "string" ? accessToken.trim() : "";
  if (!cleanAccessToken) {
    return res.status(400).json({ message: "Access token is required." });
  }

  try {
    let result: Awaited<ReturnType<typeof verifyMsg91Token>>;
    try {
      result = await verifyMsg91Token(cleanAccessToken);
    } catch (fetchErr) {
      const e = fetchErr as Error;
      logger.error("registerCustomer verifyMsg91Token threw", { message: e?.message });
      return res.status(502).json({ message: "Could not verify OTP token. Please try again." });
    }

    if (!result.ok || !result.verifiedPhone) {
      return res.status(result.status === 504 ? 504 : 401).json({
        message: "OTP verification failed. Please try again.",
      });
    }

    if (!timingSafeEqualToken(result.verifiedPhone, submittedPhone)) {
      logger.warn("registerCustomer: MSG91 token identifier mismatch against submitted phone", {
        ip: req.ip,
      });
      return res.status(403).json({
        message: "Verified mobile number does not match the submitted phone number.",
        code: "PHONE_MISMATCH",
      });
    }

    const duplicateQuery: Array<Record<string, unknown>> = [
      { phone: submittedPhone },
      { email: normalizedEmail },
      { email: { $regex: `^${escapeRegex(normalizedEmail)}$`, $options: "i" } },
    ];

    const existing = await User.findOne({ $or: duplicateQuery }).select("_id").lean();
    if (existing) {
      return res.status(409).json({
        message: "An account already exists with these details. Please sign in or use different details.",
        code: "DUPLICATE",
      });
    }

    const user = await User.create({
      username: cleanName,
      email: normalizedEmail,
      phone: submittedPhone,
      role: "CUSTOMER",
      isVerified: true,
      isActive: true,
      tokenVersion: 0,
      emailVerifiedAt: null,
    });

    await generateToken(
      {
        id: user.id,
        email: user.email ?? "",
        role: user.role,
        tokenVersion: user.tokenVersion ?? 0,
      },
      res,
    );
    logger.info("registerCustomer: created customer", { id: user.id });
    return res.status(201).json({
      message: "Account created successfully. Welcome!",
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (err: unknown) {
    if (isDuplicateKeyError(err)) {
      return res.status(409).json({
        message: "An account already exists with these details. Please sign in or use different details.",
        code: "DUPLICATE",
      });
    }
    const e = err as { message?: string; stack?: string };
    logger.error("registerCustomer error", { message: e?.message, stack: e?.stack });
    return res.status(500).json({ message: "Server error." });
  }
};

// POST /api/auth/mobile/check-phone — Retired to prevent unauthenticated phone/role enumeration
export const checkPhoneExists = async (_req: Request, res: Response) => {
  return res.status(410).json({
    message: "Phone pre-check has been retired. Proceed directly to OTP verification.",
    code: "ENDPOINT_RETIRED",
  });
};

// GET /api/auth/mobile/widget-config
export const getMsg91WidgetConfig = async (_req: Request, res: Response) => {
  return res.status(200).json({
    widgetId: env.MSG91_WIDGET_ID || "",
    tokenAuth: env.MSG91_TOKEN_AUTH || "",
  });
};
