// src/schemas/user.schema.ts
import { z } from "zod";
import {
  EMAIL_FORMAT_REGEX,
  normalizeEmail,
  normalizeUaeMobile,
} from "../utils/identity";

export const createUserSchema = z.object({
  username: z
    .string({ required_error: "Username is required" })
    .min(2, "Username must be at least 2 characters")
    .max(50)
    .trim(),
  email: z
    .string({ required_error: "Email is required" })
    .email("Invalid email address")
    .toLowerCase()
    .trim(),
  phone: z
    .string({ required_error: "Phone is required" })
    .min(7, "Phone number too short")
    .max(15, "Phone number too long"),
  password: z
    .string({ required_error: "Password is required" })
    .min(8, "Password must be at least 8 characters")
    .max(100),
  role: z
    .enum(["CUSTOMER", "ADMIN", "SUPER_ADMIN"], {
      required_error: "Role is required",
    })
    .default("CUSTOMER"),
});

export const updateProfileSchema = z.object({
  username: z.string().min(2).max(50).trim().optional(),
  phone: z
    .string()
    .min(7)
    .max(15)
    .regex(/^[0-9+\-\s()]+$/, "Invalid phone number")
    .optional(),
});

export const requestProfileUpdateSchema = z.object({
  newEmail: z
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
    }),
  newUsername: z
    .string()
    .trim()
    .min(2, "Name must be at least 2 characters")
    .max(80, "Name must be at most 80 characters")
    .optional(),
  newPhone: z
    .union([z.string(), z.null(), z.undefined()])
    .transform((val, ctx) => {
      if (val === null || val === undefined) return undefined;
      const trimmed = val.trim();
      if (!trimmed) return undefined;
      const normalized = normalizeUaeMobile(trimmed);
      if (!normalized) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Enter a valid UAE mobile number",
        });
        return z.NEVER;
      }
      return normalized;
    })
    .optional(),
});

export const resendProfileUpdateSchema = z.object({
  challengeId: z.string().trim().min(8).max(128).optional(),
});

export const verifyProfileUpdateSchema = z.object({
  otp: z
    .string({ required_error: "OTP is required", invalid_type_error: "OTP is required" })
    .trim()
    .length(6, "OTP must be exactly 6 digits")
    .regex(/^\d{6}$/, "OTP must be numeric"),
  challengeId: z.string().trim().min(8).max(128).optional(),
});

export const reviewSchema = z.object({
  rating: z
    .number({ required_error: "Rating is required" })
    .int()
    .min(1, "Rating must be between 1 and 5")
    .max(5, "Rating must be between 1 and 5"),
  comment: z.string().max(1000, "Review too long").trim().optional(),
});
