import { env } from "../config/env";
import { AppSetting } from "../models/mongoose";

export const CUSTOMER_EMAIL_OTP_FLAG_KEY = "CUSTOMER_EMAIL_OTP_ENABLED";

/**
 * Resolves whether customer-facing Email OTP signup & login endpoints/UI are active.
 * Prefers `AppSetting` (`key: "CUSTOMER_EMAIL_OTP_ENABLED"`) when explicitly configured
 * (`true`/`false` or `"true"`/`"false"`), falling back to `env.CUSTOMER_EMAIL_OTP_ENABLED`.
 * Defaults fail-closed to `false` when neither is set cleanly.
 */
export const isCustomerEmailOtpEnabled = async (): Promise<boolean> => {
  try {
    const setting = await AppSetting.findOne({ key: CUSTOMER_EMAIL_OTP_FLAG_KEY })
      .select("value")
      .lean();
    if (setting && setting.value !== undefined && setting.value !== null) {
      if (typeof setting.value === "boolean") {
        return setting.value;
      }
      if (typeof setting.value === "string") {
        const normalized = setting.value.trim().toLowerCase();
        if (normalized === "true") return true;
        if (normalized === "false") return false;
      }
    }
  } catch {
    // Fall back deterministically to validated env flag on transient AppSetting read error.
  }

  return env.CUSTOMER_EMAIL_OTP_ENABLED === "true";
};

