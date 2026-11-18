// src/utils/warehouseSettings.ts
// Reads warehouse coordinates from AppSetting table (DB-backed).
// Warehouse coordinates remain configurable for operational use.

import { AppSetting } from "../models/mongoose";
import { env } from "../config/env";

const DEFAULT_LAT = parseFloat(env.WAREHOUSE_LAT) || 25.2048;
const DEFAULT_LNG = parseFloat(env.WAREHOUSE_LNG) || 55.2708;

export interface WarehouseCoords {
  lat: number;
  lng: number;
}

export async function getWarehouseCoords(): Promise<WarehouseCoords> {
  const [latSetting, lngSetting] = await Promise.all([
    AppSetting.findOne({ key: "WAREHOUSE_LAT" }),
    AppSetting.findOne({ key: "WAREHOUSE_LNG" }),
  ]);

  return {
    lat: latSetting ? parseFloat(latSetting.value) : DEFAULT_LAT,
    lng: lngSetting ? parseFloat(lngSetting.value) : DEFAULT_LNG,
  };
}

// ── Shipping config ────────────────────────────────────────────────────────────

import type { ShippingConfig } from "../services/shipping.service";
import { UAE_EMIRATES } from "./uae";

const SHIPPING_DEFAULTS: Record<string, string> = {
  SHIPPING_UAE_FLAT_RATE_AED: "15",
  SHIPPING_UAE_EMIRATE_RATES_AED: "",
  SHIPPING_CALCULATE_COD: "true",
  SHIPPING_CALCULATE_ONLINE: "true",
};

export async function getShippingConfigFromDB(): Promise<ShippingConfig> {
  const keys = Object.keys(SHIPPING_DEFAULTS);
  const settings = await AppSetting.find({ key: { $in: keys } });
  const map: Record<string, any> = {};
  for (const s of settings) map[s.key] = s.value;

  const uaeFlatRate = Number(map["SHIPPING_UAE_FLAT_RATE_AED"] ?? 15);
  const parsedEmirateRates = map["SHIPPING_UAE_EMIRATE_RATES_AED"]
    ? JSON.parse(map["SHIPPING_UAE_EMIRATE_RATES_AED"])
    : {};
  const emirateRates = Object.fromEntries(
    UAE_EMIRATES.map((emirate) => [
      emirate,
      Number(parsedEmirateRates[emirate] ?? uaeFlatRate),
    ]),
  );

  return {
    uaeFlatRate,
    emirateRates,
    calculateShippingForCOD: map["SHIPPING_CALCULATE_COD"] !== "false" && map["SHIPPING_CALCULATE_COD"] !== false,
    calculateShippingForOnline: map["SHIPPING_CALCULATE_ONLINE"] !== "false" && map["SHIPPING_CALCULATE_ONLINE"] !== false,
  };
}
