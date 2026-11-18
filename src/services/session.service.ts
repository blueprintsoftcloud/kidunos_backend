import { Types } from "mongoose";
import type { Server } from "socket.io";
import { StaffProfile, User, type Role } from "../models/mongoose";
import logger from "../utils/logger";

export interface DecodedSessionClaims {
  id?: unknown;
  email?: unknown;
  role?: unknown;
  tokenVersion?: unknown;
}

export interface ValidatedSessionUser {
  id: string;
  email: string;
  role: Role;
  tokenVersion: number;
}

export type SessionInvalidCode =
  | "LEGACY_TOKEN"
  | "INVALID_TOKEN"
  | "USER_NOT_FOUND"
  | "ACCOUNT_DEACTIVATED"
  | "TOKEN_VERSION_MISMATCH"
  | "CLAIM_MISMATCH";

export type SessionValidationResult =
  | { valid: true; user: ValidatedSessionUser }
  | {
      valid: false;
      code: SessionInvalidCode;
      message: string;
      clearCookies: boolean;
    };

export const normalizeSessionEmail = (value: unknown): string =>
  typeof value === "string" ? value.trim().toLowerCase() : "";

export const hasValidTokenVersionClaim = (value: unknown): value is number =>
  typeof value === "number" && Number.isInteger(value) && value >= 0;

/**
 * Validates JWT claims against the current database state for ALL roles.
 * Rejects legacy tokens lacking `tokenVersion`, inactive accounts, inactive staff
 * profiles, stale `tokenVersion`s, and email/role claim drift.
 */
export const validateActiveSessionUser = async (
  decoded: DecodedSessionClaims | null | undefined,
  options: { requireEmailMatch?: boolean } = {},
): Promise<SessionValidationResult> => {
  if (!decoded || typeof decoded.id !== "string" || !Types.ObjectId.isValid(decoded.id)) {
    return {
      valid: false,
      code: "INVALID_TOKEN",
      message: "Invalid authentication token.",
      clearCookies: false,
    };
  }

  if (!hasValidTokenVersionClaim(decoded.tokenVersion)) {
    return {
      valid: false,
      code: "LEGACY_TOKEN",
      message: "Session security upgrade requires re-authentication. Please log in again.",
      clearCookies: true,
    };
  }

  const user = await User.findById(decoded.id)
    .select("_id email role isActive tokenVersion")
    .lean();

  if (!user) {
    return {
      valid: false,
      code: "USER_NOT_FOUND",
      message: "This account no longer exists.",
      clearCookies: true,
    };
  }

  if (user.isActive === false) {
    return {
      valid: false,
      code: "ACCOUNT_DEACTIVATED",
      message: "Your account has been deactivated. Please contact support.",
      clearCookies: true,
    };
  }

  const dbTokenVersion = typeof user.tokenVersion === "number" ? user.tokenVersion : 0;
  if (decoded.tokenVersion !== dbTokenVersion) {
    return {
      valid: false,
      code: "TOKEN_VERSION_MISMATCH",
      message: "Your session has been revoked. Please log in again.",
      clearCookies: true,
    };
  }

  if (typeof decoded.role !== "string" || decoded.role !== user.role) {
    return {
      valid: false,
      code: "CLAIM_MISMATCH",
      message: "Account privileges changed. Please log in again.",
      clearCookies: true,
    };
  }

  if (options.requireEmailMatch !== false) {
    const tokenEmail = normalizeSessionEmail(decoded.email);
    const dbEmail = normalizeSessionEmail(user.email);
    if (tokenEmail !== dbEmail) {
      return {
        valid: false,
        code: "CLAIM_MISMATCH",
        message: "Account email changed. Please log in again.",
        clearCookies: true,
      };
    }
  }

  if (user.role === "STAFF") {
    const staffProfile = await StaffProfile.findOne({ userId: user._id })
      .select("isActive")
      .lean();
    if (!staffProfile || staffProfile.isActive === false) {
      return {
        valid: false,
        code: "ACCOUNT_DEACTIVATED",
        message: "Your account has been deactivated. Please contact your administrator.",
        clearCookies: true,
      };
    }
  }

  return {
    valid: true,
    user: {
      id: user._id.toString(),
      email: normalizeSessionEmail(user.email),
      role: user.role as Role,
      tokenVersion: dbTokenVersion,
    },
  };
};

/**
 * Batch-validates active Socket.IO session claims against MongoDB in at most 2 queries.
 */
export const validateSocketSessionsBatch = async (
  entries: Array<{ socketId: string; claims: DecodedSessionClaims }>,
): Promise<Map<string, SessionValidationResult>> => {
  const results = new Map<string, SessionValidationResult>();
  if (entries.length === 0) return results;

  const validObjectIds: Types.ObjectId[] = [];
  const seenIds = new Set<string>();

  for (const entry of entries) {
    const { id, tokenVersion } = entry.claims;
    if (typeof id !== "string" || !Types.ObjectId.isValid(id)) {
      results.set(entry.socketId, {
        valid: false,
        code: "INVALID_TOKEN",
        message: "Invalid socket session.",
        clearCookies: true,
      });
      continue;
    }
    if (!hasValidTokenVersionClaim(tokenVersion)) {
      results.set(entry.socketId, {
        valid: false,
        code: "LEGACY_TOKEN",
        message: "Legacy socket session rejected.",
        clearCookies: true,
      });
      continue;
    }
    if (!seenIds.has(id)) {
      seenIds.add(id);
      validObjectIds.push(new Types.ObjectId(id));
    }
  }

  if (validObjectIds.length === 0) return results;

  const users = await User.find({ _id: { $in: validObjectIds } })
    .select("_id email role isActive tokenVersion")
    .lean();

  const userMap = new Map(users.map((u) => [u._id.toString(), u]));
  const staffUserObjectIds = users
    .filter((u) => u.role === "STAFF")
    .map((u) => u._id);

  const staffProfiles =
    staffUserObjectIds.length > 0
      ? await StaffProfile.find({ userId: { $in: staffUserObjectIds } })
          .select("userId isActive")
          .lean()
      : [];

  const staffActiveMap = new Map(
    staffProfiles.map((sp) => [sp.userId.toString(), sp.isActive !== false]),
  );

  for (const entry of entries) {
    if (results.has(entry.socketId)) continue;
    const { claims } = entry;
    const userId = claims.id as string;
    const user = userMap.get(userId);

    if (!user) {
      results.set(entry.socketId, {
        valid: false,
        code: "USER_NOT_FOUND",
        message: "Account no longer exists.",
        clearCookies: true,
      });
      continue;
    }

    if (user.isActive === false) {
      results.set(entry.socketId, {
        valid: false,
        code: "ACCOUNT_DEACTIVATED",
        message: "Account deactivated.",
        clearCookies: true,
      });
      continue;
    }

    const dbTokenVersion = typeof user.tokenVersion === "number" ? user.tokenVersion : 0;
    if (claims.tokenVersion !== dbTokenVersion) {
      results.set(entry.socketId, {
        valid: false,
        code: "TOKEN_VERSION_MISMATCH",
        message: "Session revoked.",
        clearCookies: true,
      });
      continue;
    }

    if (claims.role !== user.role || normalizeSessionEmail(claims.email) !== normalizeSessionEmail(user.email)) {
      results.set(entry.socketId, {
        valid: false,
        code: "CLAIM_MISMATCH",
        message: "Account claims changed.",
        clearCookies: true,
      });
      continue;
    }

    if (user.role === "STAFF" && !staffActiveMap.get(userId)) {
      results.set(entry.socketId, {
        valid: false,
        code: "ACCOUNT_DEACTIVATED",
        message: "Staff account deactivated.",
        clearCookies: true,
      });
      continue;
    }

    results.set(entry.socketId, {
      valid: true,
      user: {
        id: userId,
        email: normalizeSessionEmail(user.email),
        role: user.role as Role,
        tokenVersion: dbTokenVersion,
      },
    });
  }

  return results;
};

/**
 * Emits `session-revoked` and forcefully closes local Socket.IO connections for `userId`
 * after an out-of-band or transactional `tokenVersion` update has already committed.
 */
export const disconnectUserSockets = (
  io: Server | undefined | null,
  userId: string,
  reason: string = "SESSION_REVOKED",
): void => {
  if (!io || !userId || !Types.ObjectId.isValid(userId)) return;
  io.in(userId).emit("session-revoked", { reason });
  io.in(userId).disconnectSockets(true);
};

/**
 * Globally revokes ALL active access/refresh sessions and sockets for a single user
 * by atomically incrementing `User.tokenVersion`, wiping refresh-token state, and
 * emitting/closing local Socket.IO connections for `userId`.
 */
export const revokeUserSessions = async (
  io: Server | undefined | null,
  userId: string,
  reason: string = "SESSION_REVOKED",
): Promise<void> => {
  if (!userId || !Types.ObjectId.isValid(userId)) return;

  await User.findByIdAndUpdate(userId, {
    $inc: { tokenVersion: 1 },
    $set: {
      refreshToken: null,
      previousRefreshToken: null,
      previousRefreshTokens: [],
      refreshTokenFamily: null,
      lastRotatedAt: null,
    },
  });

  disconnectUserSockets(io, userId, reason);

  logger.info("Revoked all user sessions via tokenVersion increment", { userId, reason });
};

