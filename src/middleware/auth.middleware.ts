// src/middleware/auth.middleware.ts
// Verifies the JWT access token from the HttpOnly cookie against central session state.
// Sets req.user = { id, email, role, tokenVersion } on success.
// Returns 401 on missing, expired, legacy, or revoked tokens.

import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { env } from "../config/env";
import { clearAuthCookies } from "../config/tokens";
import {
  validateActiveSessionUser,
  type DecodedSessionClaims,
} from "../services/session.service";
import logger from "../utils/logger";

export const authMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  const token = req.cookies?.jwt as string | undefined;

  if (!token) {
    res.status(401).json({ message: "Access Denied. No token provided." });
    return;
  }

  try {
    // 1. Mathematically verify the JWT (Stateless check)
    const decoded = jwt.verify(token, env.JWT_SECRET) as DecodedSessionClaims;

    // 2. Centralized stateful validation (all roles: existence, isActive, tokenVersion,
    //    email match, and StaffProfile.isActive for STAFF)
    const validation = await validateActiveSessionUser(decoded);
    if (!validation.valid) {
      logger.warn("Auth blocked by centralized session validator", {
        code: validation.code,
        userId: typeof decoded?.id === "string" ? decoded.id : undefined,
      });
      if (validation.clearCookies && validation.code !== "LEGACY_TOKEN") {
        clearAuthCookies(res);
      }
      res.status(401).json({
        message: validation.message,
        code: validation.code,
        expired: true,
      });
      return;
    }

    // 3. Attach verified claims and proceed
    req.user = validation.user;
    next();
  } catch (err: unknown) {
    const isExpired = err instanceof Error && err.name === "TokenExpiredError";
    res.status(401).json({
      message: isExpired
        ? "Session expired. Please log in again."
        : "Invalid token.",
      expired: isExpired,
    });
  }
};

/**
 * Attaches req.user if a valid, active, versioned token is present in cookies,
 * but never rejects the request when missing, expired, or revoked.
 */
export const optionalAuthMiddleware = async (
  req: Request,
  _res: Response,
  next: NextFunction,
): Promise<void> => {
  const token = req.cookies?.jwt as string | undefined;
  if (!token) {
    next();
    return;
  }

  try {
    const decoded = jwt.verify(token, env.JWT_SECRET) as DecodedSessionClaims;
    const validation = await validateActiveSessionUser(decoded);
    if (validation.valid) {
      req.user = validation.user;
    } else {
      req.user = undefined;
    }
  } catch {
    req.user = undefined;
  }
  next();
};
