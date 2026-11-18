// src/services/shipping.service.ts
// Single source of truth for shipping calculation.
// Replaces duplicate Haversine code in orderController.js and addressController.js.

import { env } from "../config/env";
import { normalizeUaeEmirate } from "../utils/uae";

// Keep env-based warehouse as the sync default (used when callers already have coords)
export const DEFAULT_WAREHOUSE = {
  lat: parseFloat(env.WAREHOUSE_LAT) || 25.2048,
  lng: parseFloat(env.WAREHOUSE_LNG) || 55.2708,
};

// ── Configurable shipping ──────────────────────────────────────────────────────

export interface ShippingConfig {
  uaeFlatRate: number;
  emirateRates?: Record<string, number>;
  calculateShippingForCOD?: boolean;
  calculateShippingForOnline?: boolean;
}

export const DEFAULT_SHIPPING_CONFIG: ShippingConfig = {
  uaeFlatRate: 15,
  calculateShippingForCOD: true,
  calculateShippingForOnline: true,
};

export interface ShippingBreakdown {
  shippingCharge: number;
  distanceKm: number;
  type: "uae_flat_rate" | "unsupported_country";
  label: string;
}

export const calculateShippingWithConfig = async (
  _customerLat: number,
  _customerLng: number,
  country: string,
  _state: string,
  _city: string = "",
  _zipCode: string = "",
  config: ShippingConfig = DEFAULT_SHIPPING_CONFIG,
  _warehouseLat: number = DEFAULT_WAREHOUSE.lat,
  _warehouseLng: number = DEFAULT_WAREHOUSE.lng,
): Promise<ShippingBreakdown> => {
  if (country.trim().toLowerCase() !== "united arab emirates") {
    return {
      shippingCharge: 0,
      distanceKm: 0,
      type: "unsupported_country",
      label: "Delivery is only available within the United Arab Emirates",
    };
  }

  return {
    shippingCharge: config.emirateRates?.[normalizeUaeEmirate(_state) ?? ""] ?? config.uaeFlatRate,
    distanceKm: 0,
    type: "uae_flat_rate",
    label: `UAE delivery to ${normalizeUaeEmirate(_state) ?? "selected emirate"} — AED ${config.emirateRates?.[normalizeUaeEmirate(_state) ?? ""] ?? config.uaeFlatRate}`,
  };
};
