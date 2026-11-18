// src/schemas/auth.schema.ts
import { z } from "zod";
import {
  CANONICAL_UAE_PHONE_REGEX,
  EMAIL_FORMAT_REGEX,
  normalizeEmail,
} from "../utils/identity";

const requiredCustomerEmailField = z
  .string({
    required_error: "Email address is required",
    invalid_type_error: "Email address is required",
  })
  .trim()
  .min(1, "Email address is required")
  .max(254, "Email address is too long")
  .email("Enter a valid email address")
  .regex(EMAIL_FORMAT_REGEX, "Enter a valid email address")
  .transform((val, ctx) => {
    const normalized = normalizeEmail(val);
    if (!normalized) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Enter a valid email address",
      });
      return z.NEVER;
    }
    return normalized;
  });

const otpCodeField = z
  .string({ required_error: "OTP is required", invalid_type_error: "OTP is required" })
  .trim()
  .length(6, "OTP must be exactly 6 digits")
  .regex(/^\d{6}$/, "OTP must be numeric");

const challengeIdField = z
  .string({
    required_error: "Verification session challengeId is required",
    invalid_type_error: "Verification session challengeId is required",
  })
  .trim()
  .min(8, "Invalid verification session")
  .max(128, "Invalid verification session");

const optionalChallengeIdField = z
  .string()
  .trim()
  .min(8, "Invalid verification session")
  .max(128, "Invalid verification session")
  .optional();

const phoneField = z
  .string({
    required_error: "Phone number is required",
    invalid_type_error: "Phone number is required",
  })
  .trim()
  .min(1, "Phone number is required")
  .regex(CANONICAL_UAE_PHONE_REGEX, "Enter a valid 9-digit UAE mobile number starting with 5");

const accessTokenField = z
  .string({
    required_error: "Access token is required",
    invalid_type_error: "Access token is required",
  })
  .trim()
  .min(1, "Access token is required");

const customerNameField = z
  .string({
    required_error: "Full name is required",
    invalid_type_error: "Full name is required",
  })
  .trim()
  .min(2, "Name must be at least 2 characters")
  .max(80, "Name must be at most 80 characters");

export const signupSchema = z.object({
  username: z
    .string({ required_error: "Username is required" })
    .min(2, "Username must be at least 2 characters")
    .max(50, "Username must be at most 50 characters")
    .trim(),
  email: requiredCustomerEmailField,
  phone: z
    .string({ required_error: "Phone is required" })
    .min(7, "Phone number too short")
    .max(15, "Phone number too long")
    .regex(/^[0-9+\-\s()]+$/, "Invalid phone number format"),
  password: z
    .string({ required_error: "Password is required" })
    .min(8, "Password must be at least 8 characters")
    .max(100, "Password is too long"),
});

export const loginSchema = z.object({
  email: requiredCustomerEmailField,
  password: z.string({ required_error: "Password is required" }).min(1, "Password is required"),
});

export const verifyOtpSchema = z.object({
  email: requiredCustomerEmailField,
  otp: otpCodeField,
  challengeId: optionalChallengeIdField,
});

export const resendOtpSchema = z.object({
  email: requiredCustomerEmailField,
  challengeId: optionalChallengeIdField,
});

export const forgotPasswordSchema = z.object({
  email: requiredCustomerEmailField,
});

export const forgotPasswordResendSchema = z.object({
  email: requiredCustomerEmailField,
  challengeId: optionalChallengeIdField,
});

export const resetPasswordSchema = z.object({
  newPassword: z
    .string({ required_error: "New password is required" })
    .min(8, "Password must be at least 8 characters")
    .max(100, "Password is too long"),
});

// ── Customer Email OTP Signup (PR 2, feature-gated) ─────────────────────────
export const customerSignupRequestSchema = z.object({
  name: customerNameField,
  email: requiredCustomerEmailField,
  phone: phoneField,
});

export const customerSignupResendSchema = z.object({
  email: requiredCustomerEmailField,
  challengeId: challengeIdField,
});

export const customerSignupVerifySchema = z.object({
  email: requiredCustomerEmailField,
  challengeId: challengeIdField,
  otp: otpCodeField,
});

// ── Customer Email OTP Login (PR 2, feature-gated) ──────────────────────────
export const customerLoginRequestSchema = z.object({
  email: requiredCustomerEmailField,
});

export const customerLoginResendSchema = z.object({
  email: requiredCustomerEmailField,
  challengeId: challengeIdField,
});

export const customerLoginVerifySchema = z.object({
  email: requiredCustomerEmailField,
  challengeId: challengeIdField,
  otp: otpCodeField,
});

// ── Check phone exists (retired 410) ─────────────────────────────────────────
export const checkPhoneSchema = z.object({
  phone: phoneField,
});

// ── Mobile login via MSG91 Widget access token ───────────────────────────────
export const mobileLoginSchema = z.object({
  phone: phoneField,
  accessToken: accessTokenField,
});

// ── Mobile registration via MSG91 Widget OTP ─────────────────────────────────
export const mobileRegisterSchema = z.object({
  name: customerNameField,
  email: requiredCustomerEmailField,
  phone: phoneField,
  accessToken: accessTokenField,
});
