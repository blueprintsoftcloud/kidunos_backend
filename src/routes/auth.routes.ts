import { Router } from "express";
import {
  signup,
  login,
  logout,
  resendOtp,
  refreshTokens,
  verifyLoginOtp,
  mobileLogin,
  registerCustomer,
  checkPhoneExists,
  getMsg91WidgetConfig,
  getCustomerAuthConfig,
  customerSignupRequestOtp,
  customerSignupResendOtp,
  customerSignupVerifyOtp,
  customerLoginRequestOtp,
  customerLoginResendOtp,
  customerLoginVerifyOtp,
} from "../controllers/auth.controller";
import {
  forgotPassword,
  resendResetOtp,
  verifyResetOtp,
  resetPassword,
} from "../controllers/passwordReset.controller";
import jwt from "jsonwebtoken";
import { env } from "../config/env";
import { clearAuthCookies } from "../config/tokens";
import {
  validateActiveSessionUser,
  type DecodedSessionClaims,
} from "../services/session.service";
import {
  loginLimiter,
  otpLimiter,
  passwordResetLimiter,
} from "../middleware/rateLimit.middleware";
import { validate } from "../middleware/validate.middleware";
import {
  loginSchema,
  verifyOtpSchema,
  resendOtpSchema,
  forgotPasswordSchema,
  forgotPasswordResendSchema,
  resetPasswordSchema,
  customerSignupRequestSchema,
  customerSignupResendSchema,
  customerSignupVerifySchema,
  customerLoginRequestSchema,
  customerLoginResendSchema,
  customerLoginVerifySchema,
  mobileLoginSchema,
  mobileRegisterSchema,
} from "../schemas/auth.schema";

const router = Router();

// Public CSRF bootstrap endpoint — sets csrfToken cookie (via ensureCsrfCookie) and
// returns it with Cache-Control: no-store so clients can ensure a token before mutating calls.
router.get("/csrf", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const token =
    (req.cookies?.csrfToken as string | undefined) ||
    (res.locals.generatedCsrfToken as string | undefined) ||
    "";
  return res.status(200).json({ csrfToken: token });
});

// Legacy public signup permanently disabled (410 Gone)
router.post("/signup", signup);
router.post("/login", loginLimiter, validate(loginSchema), login);
router.post("/refresh", refreshTokens);
router.post("/logout", logout);
router.post("/login/verify", loginLimiter, validate(verifyOtpSchema), verifyLoginOtp);
router.post("/resend-otp", otpLimiter, validate(resendOtpSchema), resendOtp);
router.post("/forgot-password", passwordResetLimiter, validate(forgotPasswordSchema), forgotPassword);
router.post("/forgot-password/resend-otp", passwordResetLimiter, validate(forgotPasswordResendSchema), resendResetOtp);
router.post("/verify-reset-otp", passwordResetLimiter, validate(verifyOtpSchema), verifyResetOtp);
router.post("/reset-password", passwordResetLimiter, validate(resetPasswordSchema), resetPassword);

router.get("/status", async (req, res) => {
  const token = req.cookies?.jwt as string | undefined;
  const hasRefreshToken = !!req.cookies?.refreshToken;

  if (!token) {
    if (hasRefreshToken) {
      return res.status(401).json({ message: "Access token expired." });
    }
    return res.status(200).json({ isLoggedIn: false, role: null });
  }

  try {
    const decoded = jwt.verify(token, env.JWT_SECRET) as DecodedSessionClaims;
    const validation = await validateActiveSessionUser(decoded);
    if (!validation.valid) {
      if (validation.clearCookies && (!hasRefreshToken || validation.code !== "LEGACY_TOKEN")) {
        clearAuthCookies(res);
      }
      return res.status(401).json({
        isLoggedIn: false,
        role: null,
        message: validation.message,
        code: validation.code,
      });
    }
    return res.status(200).json({ isLoggedIn: true, role: validation.user.role });
  } catch (err: unknown) {
    if ((err as { name?: string }).name === "TokenExpiredError") {
      return res.status(401).json({ message: "Access token expired." });
    }
    return res.status(200).json({ isLoggedIn: false, role: null });
  }
});

// ── Customer Email OTP auth (PR 2, feature-gated until PR 4 cutover) ─────────
router.get("/customer/config", getCustomerAuthConfig);
router.post("/customer/signup/request-otp", otpLimiter, validate(customerSignupRequestSchema), customerSignupRequestOtp);
router.post("/customer/signup/resend-otp", otpLimiter, validate(customerSignupResendSchema), customerSignupResendOtp);
router.post("/customer/signup/verify-otp", loginLimiter, validate(customerSignupVerifySchema), customerSignupVerifyOtp);
router.post("/customer/login/request-otp", otpLimiter, validate(customerLoginRequestSchema), customerLoginRequestOtp);
router.post("/customer/login/resend-otp", otpLimiter, validate(customerLoginResendSchema), customerLoginResendOtp);
router.post("/customer/login/verify-otp", loginLimiter, validate(customerLoginVerifySchema), customerLoginVerifyOtp);

// ── Mobile OTP auth via MSG91 Widget (hardened prep window) ──────────────────
router.post("/mobile/check-phone", otpLimiter, checkPhoneExists);
router.post("/mobile/login", otpLimiter, validate(mobileLoginSchema), mobileLogin);
router.post("/mobile/register", otpLimiter, validate(mobileRegisterSchema), registerCustomer);
router.get("/mobile/widget-config", getMsg91WidgetConfig);

export default router;
