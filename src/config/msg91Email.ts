// src/config/msg91Email.ts
// MSG91 Email API v5 client — template-based transactional email, replacing the
// previous nodemailer/Gmail SMTP transport (see git history on config/mailer.ts).
//
// VERIFY BEFORE GOING LIVE: this request shape follows MSG91's documented v5
// Email API pattern (POST /api/v5/email/send, `authkey` header, a `recipients`
// array with per-recipient `to`/`variables`, top-level `from`/`domain`/
// `template_id`). MSG91's technical reference (docs.msg91.com/email/send-email)
// is a JS-rendered page that couldn't be fetched/verified while writing this.
// Once a template exists in MSG91's dashboard, its "API Integration" tab shows a
// ready-made snippet with your real template_id/domain filled in — cross-check
// the field names below against that snippet before relying on this in production.

import { env } from "./env";
import logger from "../utils/logger";

const MSG91_EMAIL_SEND_URL = "https://control.msg91.com/api/v5/email/send";
export const MSG91_EMAIL_TIMEOUT_MS = 8000;

export type Msg91DeliveryKind = "ambiguous_timeout" | "transient" | "permanent";

export class Msg91DeliveryError extends Error {
  public readonly deliveryKind: Msg91DeliveryKind;
  public readonly httpStatus?: number;
  public readonly errorCode: string;

  constructor(
    message: string,
    deliveryKind: Msg91DeliveryKind,
    options: { httpStatus?: number; errorCode?: string } = {},
  ) {
    super(message);
    this.name = "Msg91DeliveryError";
    this.deliveryKind = deliveryKind;
    this.httpStatus = options.httpStatus;
    this.errorCode = options.errorCode || deliveryKind.toUpperCase();
  }
}

export interface Msg91TemplateEmailData {
  to: string;
  /** Defaults to the email address itself if omitted. */
  toName?: string;
  templateId: string;
  /** Must match the {{variable}} placeholders defined in the MSG91 dashboard template. */
  variables: Record<string, string>;
  /**
   * Per-tenant sender display name (e.g. that client's own business name),
   * resolved by services/email.service.ts from the tenant's MSG91_EMAIL_FROM_NAME
   * AppSetting. Falls back to env.MSG91_EMAIL_FROM_NAME when unset — the shared
   * MSG91 account/domain/auth key stay the same for every tenant either way.
   */
  fromName?: string;
  /** When true (e.g. OTP delivery), missing MSG91 Email API configuration throws explicitly instead of no-oping. */
  throwOnMissingConfig?: boolean;
}

export const hasMsg91EmailConfig = (templateId: string): boolean =>
  Boolean(
    env.MSG91_AUTH_KEY &&
      templateId &&
      env.MSG91_EMAIL_DOMAIN &&
      env.MSG91_EMAIL_FROM,
  );

export const sendMsg91TemplateEmail = async (data: Msg91TemplateEmailData): Promise<void> => {
  if (!hasMsg91EmailConfig(data.templateId)) {
    const missingMeta = {
      hasAuthKey: Boolean(env.MSG91_AUTH_KEY),
      hasTemplateId: Boolean(data.templateId),
      hasDomain: Boolean(env.MSG91_EMAIL_DOMAIN),
      hasFrom: Boolean(env.MSG91_EMAIL_FROM),
    };
    if (data.throwOnMissingConfig) {
      logger.error("[msg91-email] missing required OTP email configuration", missingMeta);
      throw new Msg91DeliveryError(
        "MSG91 email configuration is incomplete for OTP delivery.",
        "permanent",
        { errorCode: "CONFIG_INCOMPLETE" },
      );
    }
    logger.warn(`[msg91-email] not configured — skipped send to ${data.to}`, missingMeta);
    return;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), MSG91_EMAIL_TIMEOUT_MS);

  let res: globalThis.Response;
  let rawText = "";
  try {
    res = await fetch(MSG91_EMAIL_SEND_URL, {
      method: "POST",
      headers: {
        authkey: env.MSG91_AUTH_KEY,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        recipients: [
          {
            to: [{ email: data.to, name: data.toName ?? data.to }],
            variables: data.variables,
          },
        ],
        from: {
          email: env.MSG91_EMAIL_FROM,
          name: data.fromName || env.MSG91_EMAIL_FROM_NAME,
        },
        domain: env.MSG91_EMAIL_DOMAIN,
        template_id: data.templateId,
      }),
      signal: controller.signal,
    });
    rawText = await res.text();
  } catch (err: unknown) {
    if ((err instanceof Error && err.name === "AbortError") || controller.signal.aborted) {
      throw new Msg91DeliveryError(
        `MSG91 email send timed out after ${MSG91_EMAIL_TIMEOUT_MS}ms`,
        "ambiguous_timeout",
        { errorCode: "TIMEOUT_AMBIGUOUS" },
      );
    }
    const errMessage = err instanceof Error ? err.message : "Network error sending MSG91 email";
    const errCode =
      typeof (err as { code?: unknown })?.code === "string"
        ? ((err as { code: string }).code)
        : "NETWORK_ERROR";
    throw new Msg91DeliveryError(errMessage, "transient", { errorCode: errCode });
  } finally {
    clearTimeout(timeoutId);
  }

  let body: Record<string, unknown> = {};
  try {
    body = rawText ? (JSON.parse(rawText) as Record<string, unknown>) : {};
  } catch {
    body = { raw: rawText };
  }

  const jsonStatus = typeof body.status === "string" ? body.status.toLowerCase() : "";
  const jsonType = typeof body.type === "string" ? body.type.toLowerCase() : "";
  const hasJsonError =
    body.hasError === true ||
    jsonStatus === "fail" ||
    jsonStatus === "error" ||
    jsonStatus === "failed" ||
    jsonType === "error";

  if (!res.ok || hasJsonError) {
    const isTransientHttp = res.status === 429 || res.status >= 500;
    const deliveryKind: Msg91DeliveryKind = isTransientHttp ? "transient" : "permanent";
    const errorCode = !res.ok ? `HTTP_${res.status}` : "PROVIDER_REJECTED";
    throw new Msg91DeliveryError(
      `MSG91 email send failed (${res.status}): ${JSON.stringify(body)}`,
      deliveryKind,
      { httpStatus: res.status, errorCode },
    );
  }
};
