import { Request, Response } from "express";
import mongoose from "mongoose";
import { OtpChallenge, User } from "../models/mongoose";
import { generateToken } from "../config/tokens";
import { disconnectUserSockets } from "../services/session.service";
import logger from "../utils/logger";
import {
  escapeRegex,
  normalizeEmail,
  normalizeUaeMobile,
} from "../utils/identity";
import {
  ensureOtpCollectionsInitialized,
  findLatestActiveChallenge,
  issueChallengeAndEnqueueOutbox,
  resendChallengeAndEnqueueOutbox,
  TxAbortError,
  verifyChallengeOtp,
} from "../services/otp.service";

const isDuplicateKeyError = (err: unknown): boolean => {
  if (typeof err !== "object" || err === null) return false;
  const e = err as { code?: number; cause?: { code?: number } };
  return e.code === 11000 || e.cause?.code === 11000;
};

// POST /api/user/profile/request-update  &  POST /api/admin/adminProfile/request-update
export const requestProfileUpdate = async (req: Request, res: Response) => {
  try {
    const userId = req.user!.id;
    const { newEmail: rawNewEmail, newUsername: rawUsername, newPhone: rawPhone } = req.body as {
      newEmail?: unknown;
      newUsername?: unknown;
      newPhone?: unknown;
    };

    const currentUser = await User.findById(userId)
      .select("_id username email phone role isActive tokenVersion emailVerifiedAt posActivationRequired")
      .lean();
    if (!currentUser || currentUser.isActive === false) {
      return res.status(403).json({ message: "Account is unavailable." });
    }

    const cleanNewEmail = normalizeEmail(rawNewEmail);
    if (!cleanNewEmail) {
      return res.status(400).json({ message: "A valid email address is required." });
    }

    let resolvedUsername = currentUser.username;
    if (rawUsername !== undefined && rawUsername !== null) {
      const trimmedName = typeof rawUsername === "string" ? rawUsername.trim() : "";
      if (!trimmedName || trimmedName.length < 2 || trimmedName.length > 80) {
        return res.status(400).json({ message: "Name must be between 2 and 80 characters." });
      }
      resolvedUsername = trimmedName;
    }

    let resolvedPhone: string | undefined;
    if (rawPhone !== undefined && rawPhone !== null && String(rawPhone).trim() !== "") {
      const normPhone = normalizeUaeMobile(rawPhone);
      if (!normPhone) {
        return res.status(400).json({
          message: "Enter a valid UAE mobile number.",
        });
      }
      resolvedPhone = normPhone;
    }

    // Global uniqueness checks across ALL accounts (excluding authenticated owner)
    const existingEmail = await User.findOne({
      _id: { $ne: currentUser._id },
      $or: [
        { email: cleanNewEmail },
        { email: { $regex: `^${escapeRegex(cleanNewEmail)}$`, $options: "i" } },
      ],
    })
      .select("_id")
      .lean();

    if (existingEmail) {
      return res.status(409).json({
        message: "This email is already taken by another account.",
      });
    }

    if (resolvedPhone) {
      const existingPhone = await User.findOne({
        _id: { $ne: currentUser._id },
        phone: resolvedPhone,
      })
        .select("_id")
        .lean();
      if (existingPhone) {
        return res.status(409).json({
          message: "This phone number is already taken by another account.",
        });
      }
    }

    const issued = await issueChallengeAndEnqueueOutbox({
      purpose: "profile_update",
      email: cleanNewEmail,
      toName: resolvedUsername,
      ip: req.ip,
      userId: currentUser._id,
      tokenVersionSnapshot: currentUser.tokenVersion ?? 0,
      pendingData: {
        newEmail: cleanNewEmail,
        newUsername: resolvedUsername,
        ...(resolvedPhone ? { newPhone: resolvedPhone } : {}),
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
      message: `OTP sent to ${cleanNewEmail}. Please verify to complete the update.`,
      challengeId: issued.challengeId,
      newEmail: cleanNewEmail,
      expiresInSeconds: issued.expiresInSeconds,
      resendAfterSeconds: issued.resendAfterSeconds,
    });
  } catch (err: unknown) {
    logger.error("requestProfileUpdate error", {
      message: err instanceof Error ? err.message : String(err),
    });
    return res.status(500).json({ message: "Error initiating profile update" });
  }
};

// POST /api/user/profile/resend-otp  &  POST /api/admin/adminProfile/resend-otp
export const resendProfileUpdateOtp = async (req: Request, res: Response) => {
  try {
    const userId = req.user!.id;
    const requestedChallengeId =
      typeof req.body?.challengeId === "string" ? req.body.challengeId.trim() : "";

    const activeChallenge = requestedChallengeId
      ? await findLatestActiveChallenge({ purpose: "profile_update", userId }).then(
          (latest) =>
            latest && latest.challengeId === requestedChallengeId ? latest : null,
        )
      : await findLatestActiveChallenge({ purpose: "profile_update", userId });

    if (!activeChallenge) {
      return res.status(401).json({
        message: "No active email verification request found. Please start again.",
        code: "CHALLENGE_MISSING",
      });
    }

    const resendRes = await resendChallengeAndEnqueueOutbox({
      purpose: "profile_update",
      email: activeChallenge.email,
      challengeId: activeChallenge.challengeId,
      userId,
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
      message: `New verification code sent to ${activeChallenge.email}.`,
      challengeId: resendRes.challengeId,
      newEmail: activeChallenge.email,
      expiresInSeconds: resendRes.expiresInSeconds,
      resendAfterSeconds: resendRes.resendAfterSeconds,
    });
  } catch (err: unknown) {
    logger.error("resendProfileUpdateOtp error", {
      message: err instanceof Error ? err.message : String(err),
    });
    return res.status(500).json({ message: "Error resending verification code" });
  }
};

// POST /api/user/profile/verify-update  &  POST /api/admin/adminProfile/verify-update
export const verifyAndUpdateProfile = async (req: Request, res: Response) => {
  try {
    const userId = req.user!.id;
    const { otp, challengeId } = req.body as { otp?: string; challengeId?: string };

    if (!otp || typeof otp !== "string") {
      return res.status(400).json({ message: "A 6-digit verification code is required." });
    }

    const currentUser = await User.findById(userId)
      .select("_id username email phone role isActive tokenVersion")
      .lean();
    if (!currentUser || currentUser.isActive === false) {
      return res.status(403).json({ message: "Account is unavailable." });
    }

    const activeChallenge = await findLatestActiveChallenge({
      purpose: "profile_update",
      userId,
    });

    const targetChallengeId =
      typeof challengeId === "string" && challengeId.trim()
        ? challengeId.trim()
        : activeChallenge?.challengeId;

    // Resolve the bound email for this challenge if active or explicit
    let targetEmail: string | null = activeChallenge?.email ?? null;
    if (
      targetChallengeId &&
      (!activeChallenge || activeChallenge.challengeId !== targetChallengeId)
    ) {
      const explicitDoc = await OtpChallenge.findOne({
        challengeId: targetChallengeId,
        purpose: "profile_update",
        userId: currentUser._id,
      })
        .select("email")
        .lean();
      targetEmail = explicitDoc?.email ?? null;
    }

    if (!targetChallengeId || !targetEmail) {
      return res.status(401).json({
        message: "Invalid or expired OTP.",
        code: "CHALLENGE_INVALID",
      });
    }

    await ensureOtpCollectionsInitialized();
    const session = await mongoose.startSession();

    let updatedUserView: {
      id: string;
      username: string;
      email: string | null;
      phone: string | null;
      role: string;
      emailVerifiedAt: Date | null;
      posActivationRequired: boolean;
      tokenVersion: number;
    } | null = null;
    let emailChanged = false;
    let txFailure: {
      httpStatus: number;
      code: string;
      message: string;
      attemptsRemaining?: number;
      retryAfterSeconds?: number;
    } | null = null;

    try {
      await session.withTransaction(async () => {
        updatedUserView = null;
        emailChanged = false;
        txFailure = null;

        const verifyRes = await verifyChallengeOtp({
          purpose: "profile_update",
          email: targetEmail!,
          otp,
          challengeId: targetChallengeId,
          userId: currentUser._id,
          ip: req.ip,
          session,
        });

        if (!verifyRes.ok) {
          txFailure = {
            httpStatus: verifyRes.httpStatus,
            code: verifyRes.code,
            message: verifyRes.message,
            attemptsRemaining: verifyRes.attemptsRemaining,
            retryAfterSeconds: verifyRes.retryAfterSeconds,
          };
          throw new TxAbortError();
        }

        const pending = (verifyRes.challenge.pendingData ?? {}) as {
          newEmail?: unknown;
          newUsername?: unknown;
          newPhone?: unknown;
        };

        const pendingEmail = normalizeEmail(pending.newEmail);
        if (!pendingEmail || pendingEmail !== verifyRes.challenge.email) {
          txFailure = {
            httpStatus: 400,
            code: "CHALLENGE_INVALID",
            message: "Verification payload does not match target email.",
          };
          throw new TxAbortError();
        }

        const priorUser = await User.findById(currentUser._id).session(session);
        if (!priorUser || priorUser.isActive === false) {
          txFailure = {
            httpStatus: 403,
            code: "ACCOUNT_DEACTIVATED",
            message: "Account is unavailable.",
          };
          throw new TxAbortError();
        }

        const priorNormEmail = normalizeEmail(priorUser.email) ?? "";
        emailChanged = priorNormEmail !== pendingEmail;

        const updateSet: Record<string, unknown> = {
          email: pendingEmail,
          emailVerifiedAt: new Date(),
          posActivationRequired: false,
        };

        if (typeof pending.newUsername === "string" && pending.newUsername.trim().length >= 2) {
          updateSet.username = pending.newUsername.trim();
        }

        if (pending.newPhone !== undefined && pending.newPhone !== null) {
          const normPhone = normalizeUaeMobile(pending.newPhone);
          if (normPhone) {
            updateSet.phone = normPhone;
          }
        }

        const updateQuery: Record<string, unknown> = {
          $set: {
            ...updateSet,
            ...(emailChanged
              ? {
                  refreshToken: null,
                  previousRefreshToken: null,
                  previousRefreshTokens: [],
                  refreshTokenFamily: null,
                  lastRotatedAt: null,
                }
              : {}),
          },
        };

        if (emailChanged) {
          updateQuery.$inc = { tokenVersion: 1 };
        }

        const saved = await User.findByIdAndUpdate(currentUser._id, updateQuery, {
          new: true,
          session,
        });

        if (!saved) {
          txFailure = {
            httpStatus: 404,
            code: "USER_NOT_FOUND",
            message: "Account not found.",
          };
          throw new TxAbortError();
        }

        updatedUserView = {
          id: saved.id,
          username: saved.username,
          email: saved.email ?? null,
          phone: saved.phone ?? null,
          role: saved.role,
          emailVerifiedAt: saved.emailVerifiedAt ?? null,
          posActivationRequired: Boolean(saved.posActivationRequired),
          tokenVersion: saved.tokenVersion ?? 0,
        };
      });
    } catch (txErr: unknown) {
      if (!(txErr instanceof TxAbortError)) {
        if (isDuplicateKeyError(txErr)) {
          return res.status(409).json({
            message: "The new email address or phone number is already in use.",
          });
        }
        throw txErr;
      }
    } finally {
      await session.endSession();
    }

    if (txFailure) {
      const f = txFailure as {
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

    if (!updatedUserView) {
      return res.status(500).json({ message: "Error updating profile." });
    }

    const finalUser = updatedUserView as {
      id: string;
      username: string;
      email: string | null;
      phone: string | null;
      role: string;
      emailVerifiedAt: Date | null;
      posActivationRequired: boolean;
      tokenVersion: number;
    };

    if (emailChanged) {
      disconnectUserSockets(req.app.get("socketio"), userId, "EMAIL_UPDATED");
      await generateToken(
        {
          id: finalUser.id,
          email: finalUser.email ?? "",
          role: finalUser.role,
          tokenVersion: finalUser.tokenVersion,
        },
        res,
      );
    }

    return res.status(200).json({
      message: "Profile updated successfully.",
      user: {
        id: finalUser.id,
        username: finalUser.username,
        email: finalUser.email,
        phone: finalUser.phone,
        role: finalUser.role,
        emailVerifiedAt: finalUser.emailVerifiedAt,
        posActivationRequired: finalUser.posActivationRequired,
      },
    });
  } catch (err: unknown) {
    logger.error("verifyAndUpdateProfile error", {
      message: err instanceof Error ? err.message : String(err),
    });
    return res.status(500).json({ message: "Error updating profile." });
  }
};
