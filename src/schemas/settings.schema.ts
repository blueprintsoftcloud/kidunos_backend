// src/schemas/settings.schema.ts
import { z } from "zod";

export const updateWarehouseSettingsSchema = z.object({
  lat: z.coerce.number().min(-90).max(90),
  lng: z.coerce.number().min(-180).max(180),
  name: z.string().max(200).trim().optional(),
});

export const updateShippingConfigSchema = z.object({
  uaeFlatRate: z.coerce.number().finite().min(0).max(10000).optional(),
  emirateRates: z.record(z.string().trim().min(1), z.coerce.number().finite().min(0).max(10000)).optional(),
  calculateShippingForCOD: z.boolean().optional(),
  calculateShippingForOnline: z.boolean().optional(),
}).refine((value) => value.uaeFlatRate !== undefined || value.emirateRates !== undefined || value.calculateShippingForCOD !== undefined || value.calculateShippingForOnline !== undefined, {
  message: "At least one shipping setting must be provided",
});
export const updateTrackingPartnerSettingsSchema = z.object({
  enabled: z.boolean(),
  enabledPartners: z.array(z.string().trim()).default([]),
  partnerUrls: z.record(z.string(), z.string()).optional(),
  deletedPartners: z.array(z.string().trim()).optional(),
});
