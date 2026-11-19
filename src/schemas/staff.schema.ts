// src/schemas/staff.schema.ts
import { z } from "zod";
import { normalizeIndianMobile, normalizeUaeMobile } from "../utils/identity";

const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}$/;

const staffPhoneSchema = z
  .string({ required_error: "Phone number is required" })
  .trim()
  .min(1, "Phone number is required")
  .transform((val, ctx) => {
    const normalized = normalizeUaeMobile(val) ?? normalizeIndianMobile(val);
    if (!normalized) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Phone must be a valid UAE mobile number (e.g. 50 123 4567 or 050 123 4567) or 10-digit Indian mobile number",
      });
      return z.NEVER;
    }
    return normalized;
  });

export const staffCreateSchema = z.object({
  username: z.string().min(3, "Username must be at least 3 characters").trim(),
  email: z.string().regex(emailRegex, "Invalid email address format"),
  phone: staffPhoneSchema,
  password: z.string().min(6, "Password must be at least 6 characters"),
  permissions: z.array(z.string()).optional(),
  notes: z.string().max(1000).optional(),
});

export const staffUpdateSchema = z.object({
  username: z.string().min(3).trim().optional(),
  email: z.string().regex(emailRegex, "Invalid email address format").optional(),
  phone: staffPhoneSchema.optional(),
  notes: z.string().max(1000).optional(),
  newPassword: z.union([z.string().min(6), z.literal("")]).optional(),
});

export const staffUpdatePermissionsSchema = z.object({
  permissions: z.array(z.string()),
});

export const staffMyProfileUpdateSchema = z.object({
  username: z.string().min(3, "Username must be at least 3 characters").trim(),
});
