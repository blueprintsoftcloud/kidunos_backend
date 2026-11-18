import jwt from "jsonwebtoken";
import crypto from "crypto";
import { Response } from "express";
import { User } from "../models/index";
import { env } from "./env";

const generateRefreshTokenValue = () => crypto.randomBytes(32).toString("hex");

/** Computes the SHA-256 hex digest stored in MongoDB instead of plaintext refresh token values. */
export const hashRefreshTokenValue = (tokenValue: string): string =>
  crypto.createHash("sha256").update(tokenValue, "utf8").digest("hex");

/** Constant-time string comparison guarding against unequal-length Buffer exceptions. */
export const timingSafeEqualToken = (a: string, b: string): boolean => {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
};

export const getAuthCookieOptions = () => {
  const isProd = env.NODE_ENV === "production";
  return {
    httpOnly: true,
    sameSite: (isProd ? "none" : "lax") as "none" | "lax",
    secure: isProd,
  };
};

export const clearAuthCookies = (res: Response): void => {
  const opts = getAuthCookieOptions();
  res.clearCookie("jwt", { ...opts, path: "/" });
  res.clearCookie("refreshToken", { ...opts, path: "/" });
  // Purge any stale cookies written under legacy paths in older deployments.
  for (const stalePath of ["/api/auth/refresh", "/api/auth", "/api"]) {
    res.clearCookie("jwt", { ...opts, path: stalePath });
    res.clearCookie("refreshToken", { ...opts, path: stalePath });
  }
};

/**
 * Issues a fresh access/refresh token pair containing the current `tokenVersion`
 * and stores only SHA-256 digests of the refresh-token secret in MongoDB.
 *
 * `family` identifies one continuous login session across refreshes — reuse-detection
 * (see auth.controller.ts's refreshTokens) depends on it never changing across a
 * rotation. Omit it on a genuine login/signup (starts a brand new family); pass the
 * existing family through on a refresh (rotates the token value but keeps the family).
 */
export const generateToken = async (
  user: { id: string; email: string; role: string; tokenVersion?: number },
  res: Response,
  family: string = crypto.randomUUID(),
): Promise<void> => {
  // Always read the authoritative tokenVersion, email, and role from MongoDB so newly
  // minted tokens remain consistent with database revocation state.
  const currentUser = await User.findById(user.id)
    .select("email role tokenVersion refreshToken refreshTokenFamily previousRefreshTokens")
    .lean();

  const currentTokenVersion =
    typeof currentUser?.tokenVersion === "number"
      ? currentUser.tokenVersion
      : (user.tokenVersion ?? 0);
  const normalizedEmail = (currentUser?.email ?? user.email ?? "").trim().toLowerCase();
  const resolvedRole = currentUser?.role ?? user.role;

  const accessToken = jwt.sign(
    {
      id: user.id,
      email: normalizedEmail,
      role: resolvedRole,
      tokenVersion: currentTokenVersion,
    },
    env.JWT_SECRET,
    { expiresIn: "16m" },
  );

  const refreshTokenValue = generateRefreshTokenValue();
  const refreshTokenDigest = hashRefreshTokenValue(refreshTokenValue);
  const refreshToken = jwt.sign(
    {
      id: user.id,
      tokenValue: refreshTokenValue,
      family,
      tokenVersion: currentTokenVersion,
    },
    env.REFRESH_TOKEN_SECRET,
    { expiresIn: "7d" },
  );

  const now = new Date();
  const GRACE_WINDOW_MS = 15 * 60 * 1000; // 15 minutes grace window
  const isSameFamily =
    Boolean(currentUser?.refreshTokenFamily) && currentUser?.refreshTokenFamily === family;

  // Keep only rotated SHA-256 digests from the same session family within the grace window.
  const existingRecent = isSameFamily
    ? (currentUser?.previousRefreshTokens || [])
        .filter(
          (item) =>
            item.token &&
            now.getTime() - new Date(item.rotatedAt).getTime() < GRACE_WINDOW_MS,
        )
        .slice(-20)
    : [];

  // Record prior rotated digest when continuing a session family.
  if (
    isSameFamily &&
    currentUser?.refreshToken &&
    currentUser.refreshToken !== refreshTokenDigest
  ) {
    existingRecent.push({
      token: currentUser.refreshToken,
      rotatedAt: now,
    });
  }

  await User.findByIdAndUpdate(user.id, {
    refreshToken: refreshTokenDigest,
    previousRefreshToken: isSameFamily ? (currentUser?.refreshToken || null) : null,
    previousRefreshTokens: existingRecent,
    refreshTokenFamily: family,
    lastRotatedAt: now,
  });

  const cookieOpts = getAuthCookieOptions();
  for (const stalePath of ["/api/auth/refresh", "/api/auth", "/api"]) {
    res.clearCookie("jwt", { ...cookieOpts, path: stalePath });
    res.clearCookie("refreshToken", { ...cookieOpts, path: stalePath });
  }

  res.cookie("jwt", accessToken, {
    maxAge: 16 * 60 * 1000, // 16 min
    ...cookieOpts,
    path: "/",
  });

  res.cookie("refreshToken", refreshToken, {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    ...cookieOpts,
    path: "/",
  });
};
