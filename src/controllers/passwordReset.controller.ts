import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import { StaffProfile, User } from "../models/mongoose";
import { env } from "../config/env";
import { getAuthCookieOptions } from "../config/tokens";
import { disconnectUserSockets } from "../services/session.service";
import logger from "../utils/logger";
import { escapeRegex, normalizeEmail } from "../utils/identity";
import {
  attachResetTokenJti,
  consumeResetTokenJti,
  ensureOtpCollectionsInitialized,
  findLatestActiveChallenge,
  issueChallengeAndEnqueueOutbox,
  resendChallengeAndEnqueueOutbox,
  TxAbortError,
  verifyChallengeOtp,
} from "../services/otp.service";

const INTERNAL_RESET_ROLES = new Set(["ADMIN", "STAFF", "SUPER_ADMIN"]);
const GENERIC_FORGOT_PASSWORD_MESSAGE =
  "If an eligible account exists for this email, a verification code has been sent.";

const isActiveInternalResetUser = async (
  user: { _id: mongoose.Types.ObjectId; role: string; isActive?: boolean } | null,
): Promise<boolean> => {
  if (!user) return false;
  if (!INTERNAL_RESET_ROLES.has(user.role)) return false;
  if (user.isActive === false) return false;

  if (user.role === "STAFF") {
    const staffProfile = await StaffProfile.findOne({ userId: user._id })
      .select("isActive")
      .lean();
    if (!staffProfile || staffProfile.isActive === false) {
      return false;
    }
  }

  return true;
};

// POST /api/auth/forgot-password
export const forgotPassword = async (req: Request, res: Response) => {
  try {
    const email = normalizeEmail(req.body?.email);
    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const user = await User.findOne({
      $or: [
        { email },
        { email: { $regex: `^${escapeRegex(email)}$`, $options: "i" } },
      ],
    })
      .select("_id username role isActive")
      .lean();

    const eligible = await isActiveInternalResetUser(user);

    const issued = await issueChallengeAndEnqueueOutbox({
      purpose: "password_reset",
      email,
      toName: eligible && user ? user.username : email,
      ip: req.ip,
      isDecoy: !eligible,
      userId: eligible && user ? user._id : null,
    });

    if (!issued.ok) {
      return res.status(issued.httpStatus).json({
        message: issued.message,
        code: issued.code,
        ...(issued.retryAfterSeconds ? { retryAfterSeconds: issued.retryAfterSeconds } : {}),
      });
    }

    return res.status(200).json({
      message: GENERIC_FORGOT_PASSWORD_MESSAGE,
      challengeId: issued.challengeId,
      expiresInSeconds: issued.expiresInSeconds,
      resendAfterSeconds: issued.resendAfterSeconds,
    });
  } catch (err: unknown) {
    logger.error("forgotPassword error", {
      message: err instanceof Error ? err.message : String(err),
    });
    return res.status(500).json({ message: "Error processing password reset request." });
  }
};

// POST /api/auth/forgot-password/resend-otp
export const resendResetOtp = async (req: Request, res: Response) => {
  try {
    const email = normalizeEmail(req.body?.email);
    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const requestedChallengeId =
      typeof req.body?.challengeId === "string" ? req.body.challengeId.trim() : "";

    const targetChallenge = requestedChallengeId
      ? { challengeId: requestedChallengeId }
      : await findLatestActiveChallenge({ purpose: "password_reset", email });

    if (!targetChallenge) {
      return res.status(401).json({
        message: "Active password reset challenge is required before resending.",
        code: "CHALLENGE_MISSING",
      });
    }

    const resendRes = await resendChallengeAndEnqueueOutbox({
      purpose: "password_reset",
      email,
      challengeId: targetChallenge.challengeId,
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
      message: GENERIC_FORGOT_PASSWORD_MESSAGE,
      challengeId: resendRes.challengeId,
      expiresInSeconds: resendRes.expiresInSeconds,
      resendAfterSeconds: resendRes.resendAfterSeconds,
    });
  } catch (err: unknown) {
    logger.error("resendResetOtp error", {
      message: err instanceof Error ? err.message : String(err),
    });
    return res.status(500).json({ message: "Error resending reset OTP." });
  }
};

// POST /api/auth/verify-reset-otp
export const verifyResetOtp = async (req: Request, res: Response) => {
  try {
    const { otp, challengeId } = req.body as { otp?: string; challengeId?: string };
    const email = normalizeEmail(req.body?.email);
    if (!email || !otp) {
      return res.status(400).json({ message: "Email and 6-digit OTP are required." });
    }

    const verifyRes = await verifyChallengeOtp({
      purpose: "password_reset",
      email,
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

    const user = await User.findOne({
      $or: [
        { email },
        { email: { $regex: `^${escapeRegex(email)}$`, $options: "i" } },
      ],
    })
      .select("_id role isActive")
      .lean();

    if (!(await isActiveInternalResetUser(user)) || !user) {
      return res.status(403).json({
        message: "Password reset is not permitted for this account.",
        code: "ROLE_RESTRICTED",
      });
    }

    const jtiInfo = await attachResetTokenJti({
      challengeObjectId: verifyRes.challenge._id as mongoose.Types.ObjectId,
      userId: user._id,
    });

    if (!jtiInfo) {
      return res.status(401).json({
        message: "Verification session is no longer valid. Please request a new reset code.",
        code: "CHALLENGE_INVALID",
      });
    }

    const resetToken = jwt.sign(
      {
        id: user._id.toString(),
        email,
        purpose: "password_reset",
        jti: jtiInfo.jti,
      },
      env.JWT_SECRET,
      { expiresIn: "10m" },
    );

    res.cookie("reset_token", resetToken, {
      maxAge: 10 * 60 * 1000,
      ...getAuthCookieOptions(),
      path: "/",
    });

    return res.status(200).json({
      message: "OTP Verified. You may now reset your password.",
    });
  } catch (err: unknown) {
    logger.error("verifyResetOtp error", {
      message: err instanceof Error ? err.message : String(err),
    });
    return res.status(500).json({ message: "Error verifying OTP" });
  }
};

// POST /api/auth/reset-password
export const resetPassword = async (req: Request, res: Response) => {
  try {
    const { newPassword } = req.body as { newPassword?: string };
    const resetToken = req.cookies?.reset_token as string | undefined;

    if (!resetToken) {
      return res
        .status(401)
        .json({ message: "Unauthorized. Missing reset token." });
    }

    let decoded: { id?: string; email?: string; purpose?: string; jti?: string };
    try {
      decoded = jwt.verify(resetToken, env.JWT_SECRET) as {
        id?: string;
        email?: string;
        purpose?: string;
        jti?: string;
      };
    } catch {
      return res
        .status(401)
        .json({ message: "Invalid or expired reset token." });
    }

    if (
      decoded.purpose !== "password_reset" ||
      typeof decoded.jti !== "string" ||
      !decoded.jti
    ) {
      return res.status(401).json({
        message: "Invalid or single-use claim missing in reset token.",
        code: "RESET_TOKEN_INVALID",
      });
    }

    const normalizedEmail = normalizeEmail(decoded.email);
    if (!normalizedEmail) {
      return res.status(401).json({
        message: "Invalid email claim in reset token.",
        code: "RESET_TOKEN_INVALID",
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword ?? "", 10);
    await ensureOtpCollectionsInitialized();

    const session = await mongoose.startSession();
    let targetUserId: string | null = null;
    let txFailure: { status: number; code: string; message: string } | null = null;

    try {
      await session.withTransaction(async () => {
        targetUserId = null;
        txFailure = null;

        const user = await User.findOne({
          $or: [
            { email: normalizedEmail },
            { email: { $regex: `^${escapeRegex(normalizedEmail)}$`, $options: "i" } },
          ],
        })
          .select("_id role isActive")
          .session(session)
          .lean();

        if (!user || !INTERNAL_RESET_ROLES.has(user.role) || user.isActive === false) {
          txFailure = {
            status: 403,
            code: "ROLE_RESTRICTED",
            message: "Password reset is not permitted for this account.",
          };
          throw new TxAbortError();
        }

        if (user.role === "STAFF") {
          const staffProfile = await StaffProfile.findOne({ userId: user._id })
            .select("isActive")
            .session(session)
            .lean();
          if (!staffProfile || staffProfile.isActive === false) {
            txFailure = {
              status: 403,
              code: "ACCOUNT_DEACTIVATED",
              message: "Password reset is not permitted for this deactivated account.",
            };
            throw new TxAbortError();
          }
        }

        const jtiRes = await consumeResetTokenJti({
          jti: decoded.jti!,
          email: normalizedEmail,
          userId: user._id,
          session,
        });

        if (!jtiRes.ok) {
          txFailure = {
            status: 401,
            code: jtiRes.code,
            message: jtiRes.message,
          };
          throw new TxAbortError();
        }

        const updatedUser = await User.findByIdAndUpdate(
          user._id,
          {
            $set: {
              password: hashedPassword,
              refreshToken: null,
              previousRefreshToken: null,
              previousRefreshTokens: [],
              refreshTokenFamily: null,
              lastRotatedAt: null,
            },
            $inc: { tokenVersion: 1 },
          },
          { new: true, session },
        );

        if (!updatedUser) {
          txFailure = {
            status: 404,
            code: "USER_NOT_FOUND",
            message: "Account not found.",
          };
          throw new TxAbortError();
        }

        targetUserId = user._id.toString();
      });
    } catch (txErr: unknown) {
      if (!(txErr instanceof TxAbortError)) {
        throw txErr;
      }
    } finally {
      await session.endSession();
    }

    if (txFailure) {
      const failure = txFailure as { status: number; code: string; message: string };
      return res.status(failure.status).json({
        message: failure.message,
        code: failure.code,
      });
    }

    if (targetUserId) {
      disconnectUserSockets(
        req.app.get("socketio"),
        targetUserId,
        "PASSWORD_RESET",
      );
      logger.info("Revoked all sessions after transactional password reset", {
        userId: targetUserId,
      });
    }

    res.clearCookie("reset_token", {
      ...getAuthCookieOptions(),
      path: "/",
    });

    return res.status(200).json({
      message: "Password reset successfully. You can now login.",
    });
  } catch (err: unknown) {
    logger.error("resetPassword error", {
      message: err instanceof Error ? err.message : String(err),
    });
    return res.status(500).json({ message: "Error resetting password" });
  }
};
