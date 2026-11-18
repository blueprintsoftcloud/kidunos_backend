// src/middleware/csrf.middleware.ts
//
// Double-submit-cookie + Origin/Referer CSRF protection for all mutating browser routes
// under `/api/*` (including public auth/OTP routes and anonymous storefront mutations),
// exempting strictly verified server-to-server webhooks (`/order/razorpay-webhook`).

import { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import { env } from "../config/env";

const COOKIE_NAME = "csrfToken";
const HEADER_NAME = "x-csrf-token";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

// Exact verified server-to-server webhook paths relative to the `/api` mount point
const CSRF_EXEMPT_API_PATHS = new Set(["/order/razorpay-webhook"]);

const cookieOptions = () => {
  const isProd = env.NODE_ENV === "production";
  return {
    httpOnly: false, // readable by client JS so it can be echoed as X-CSRF-Token
    sameSite: (isProd ? "none" : "lax") as "none" | "lax",
    secure: isProd,
    path: "/",
  };
};

const normalizeOrigin = (value: string): string => value.trim().replace(/\/+$/, "");

const parseAllowedOrigins = (): Set<string> =>
  new Set(
    env.ALLOWED_ORIGINS.split(",")
      .map(normalizeOrigin)
      .filter(Boolean),
  );

const extractRequestOrigin = (req: Request): string | null => {
  const originHeader = req.get("origin");
  if (typeof originHeader === "string" && originHeader.trim()) {
    const trimmed = originHeader.trim();
    if (trimmed.toLowerCase() === "null") return null;
    try {
      return normalizeOrigin(new URL(trimmed).origin);
    } catch {
      return null;
    }
  }

  const refererHeader = req.get("referer");
  if (typeof refererHeader === "string" && refererHeader.trim()) {
    try {
      const parsed = new URL(refererHeader.trim());
      return parsed.origin === "null" ? null : normalizeOrigin(parsed.origin);
    } catch {
      return null;
    }
  }

  return null;
};

const timingSafeEqualStrings = (a: string, b: string): boolean => {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
};

export const ensureCsrfCookie = (req: Request, res: Response, next: NextFunction) => {
  if (!req.cookies?.[COOKIE_NAME]) {
    const token = crypto.randomBytes(32).toString("hex");
    res.cookie(COOKIE_NAME, token, cookieOptions());
    // Attach generated token onto res.locals (NOT req.cookies) so bootstrap endpoints
    // can return it if needed without letting un-cookied mutations self-satisfy CSRF.
    res.locals.generatedCsrfToken = token;
  }
  next();
};

export const csrfProtection = (req: Request, res: Response, next: NextFunction) => {
  if (SAFE_METHODS.has(req.method.toUpperCase())) return next();

  const normalizedPath = (req.path || "").replace(/\/+$/, "") || "/";
  if (CSRF_EXEMPT_API_PATHS.has(normalizedPath)) {
    return next();
  }

  // 1. Enforce Origin / Referer allowlist
  const requestOrigin = extractRequestOrigin(req);
  const allowedOrigins = parseAllowedOrigins();
  if (!requestOrigin || !allowedOrigins.has(requestOrigin)) {
    res.status(403).json({
      message: "Request origin is not allowed.",
      code: "CSRF_ORIGIN_INVALID",
    });
    return;
  }

  // 2. Enforce double-submit CSPRNG cookie === X-CSRF-Token header using constant-time byte compare
  const cookieToken = req.cookies?.[COOKIE_NAME];
  const rawHeader = req.headers[HEADER_NAME];
  const headerToken = typeof rawHeader === "string" ? rawHeader : undefined;

  if (
    typeof cookieToken !== "string" ||
    !cookieToken ||
    !headerToken ||
    !timingSafeEqualStrings(cookieToken, headerToken)
  ) {
    res.status(403).json({
      message: "CSRF token missing or invalid.",
      code: "CSRF_INVALID",
    });
    return;
  }

  next();
};
