// src/schemas/order.schema.ts
import { z } from "zod";
import mongoose from "mongoose";
import { normalizeEmail, normalizeUaeMobile } from "../utils/identity";

export const verifyPaymentSchema = z.object({
  razorpay_order_id: z
    .string({ required_error: "Razorpay order ID is required" })
    .min(1),
  razorpay_payment_id: z
    .string({ required_error: "Razorpay payment ID is required" })
    .min(1),
  razorpay_signature: z
    .string({ required_error: "Razorpay signature is required" })
    .min(1),
  buyNowProductId: z.string().optional(),
  buyNowVariantId: z.string().nullable().optional(),
});

export const verifyNomodPaymentSchema = z.object({
  orderId: z.string().trim().min(1, "Order ID is required"),
});

export const updateOrderStatusSchema = z
  .object({
    orderStatus: z.enum(
      ["PROCESSING", "CONFIRMED", "SHIPPED", "DELIVERED", "CANCELLED"],
      { required_error: "Order status is required" },
    ),
    // Only meaningful when orderStatus === "SHIPPED" — see the superRefine below.
    deliveryPartnerId: z.string().trim().min(1).optional(),
    newDeliveryPartnerName: z.string().trim().min(1).optional(),
    // Manual/self-delivery — explicitly opts out of picking a delivery partner. When
    // true, trackingId is not required either (a self-delivered order may not have one).
    noDeliveryPartner: z.boolean().optional(),
    trackingId: z.string().trim().min(1).optional(),
    trackingLink: z.string().trim().url("Tracking link must be a valid URL").optional().or(z.literal("")),
    // Manual/self-delivery only — a free-text note in place of courier/tracking fields.
    shippingNote: z.string().trim().max(500).optional(),
    // When cancelling a paid order, admin can optionally mark as refunded immediately
    refundPayment: z.boolean().optional(),
    refundNote: z.string().trim().max(500).optional(),
  })
  .superRefine((data, ctx) => {
    if (data.orderStatus !== "SHIPPED" || data.noDeliveryPartner) return;
    if (!data.deliveryPartnerId && !data.newDeliveryPartnerName) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["deliveryPartnerId"],
        message: "Select or add a delivery partner before marking the order shipped",
      });
    }
    if (!data.trackingId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["trackingId"],
        message: "Tracking ID is required before marking the order shipped",
      });
    }
  });

const posPhoneSchema = z
  .string({
    required_error: "Phone number is required",
    invalid_type_error: "Phone number is required",
  })
  .trim()
  .min(1, "Phone number is required")
  .transform((val, ctx) => {
    const normalized = normalizeUaeMobile(val);
    if (!normalized) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Enter a valid UAE mobile number",
      });
      return z.NEVER;
    }
    return normalized;
  });

const posEmailSchema = z
  .string({
    required_error: "Email address is required",
    invalid_type_error: "Email address is required",
  })
  .trim()
  .min(1, "Email address is required")
  .max(254, "Email address is too long")
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

export const newPosCustomerSchema = z.object({
  username: z
    .string({
      required_error: "Customer name is required",
      invalid_type_error: "Customer name is required",
    })
    .trim()
    .min(2, "Customer name must be at least 2 characters")
    .max(80, "Customer name must be at most 80 characters"),
  phone: posPhoneSchema,
  email: posEmailSchema,
});

const posAddressSchema = z
  .object({
    fullAddress: z.string().nullable().optional(),
    locality: z.string().nullable().optional(),
    city: z.string().nullable().optional(),
    state: z.string().nullable().optional(),
    zipCode: z.string().nullable().optional(),
    country: z.string().nullable().optional(),
  })
  .nullable()
  .optional();

export const placeAdminOrderSchema = z
  .object({
    customerId: z.string().trim().min(1).nullable().optional(),
    newCustomer: newPosCustomerSchema.optional(),
    items: z
      .array(
        z.object({
          productId: z.string().trim().min(1, "Product ID is required"),
          variantId: z.string().trim().min(1).nullable().optional(),
          quantity: z.coerce.number().int().min(1, "Quantity must be at least 1"),
        }),
      )
      .min(1, "At least one item is required"),
    address: posAddressSchema,
    paymentMethod: z.enum(["CASH", "POD"]).default("CASH"),
    paymentNote: z.string().nullable().optional(),
    couponId: z.string().nullable().optional(),
    bypassRecentOrderWarning: z.boolean().optional(),
  })
  .superRefine((data, ctx) => {
    if (!data.customerId && !data.newCustomer) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["customerId"],
        message: "Provide either customerId or newCustomer details",
      });
    }
  });

const posObjectIdField = z
  .string({ required_error: "Customer ID is required", invalid_type_error: "Customer ID is required" })
  .trim()
  .refine((val) => mongoose.Types.ObjectId.isValid(val), "Invalid customer ID");

export const posVerifyRequestSchema = z.object({
  customerId: posObjectIdField,
  email: z.string().trim().optional(),
});

export const posVerifyResendSchema = z.object({
  customerId: posObjectIdField,
  challengeId: z
    .string({ required_error: "Verification session is required" })
    .trim()
    .min(8, "Invalid verification session")
    .max(128, "Invalid verification session"),
});

export const posVerifyOtpSchema = z.object({
  customerId: posObjectIdField,
  challengeId: z
    .string({ required_error: "Verification session is required" })
    .trim()
    .min(8, "Invalid verification session")
    .max(128, "Invalid verification session"),
  otp: z
    .string({ required_error: "OTP is required" })
    .trim()
    .length(6, "OTP must be exactly 6 digits")
    .regex(/^\d{6}$/, "OTP must be numeric"),
});
