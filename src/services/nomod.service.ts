import { env } from "../config/env";

const NOMOD_API_URL = "https://api.nomod.com/v1";

export interface NomodCheckoutItem {
  item_id: string;
  name: string;
  quantity: number;
  unit_amount: string;
}

export interface CreateNomodCheckoutInput {
  reference_id: string;
  amount: string;
  currency: "AED";
  items: NomodCheckoutItem[];
  discount?: string;
  customer?: {
    first_name?: string;
    last_name?: string;
    email?: string;
    phone_number?: string;
  };
  success_url: string;
  failure_url: string;
  cancelled_url: string;
  metadata?: Record<string, string>;
}

export interface NomodCheckoutSession {
  id: string;
  url: string;
  status: string | { status?: string };
  amount: number;
  currency: string;
  reference_id: string;
  charges?: Array<{ id?: string; status?: string; payment_method?: string }>;
}

export const getNomodCustomerName = (
  username: string | null | undefined,
): { first_name: string; last_name: string } => {
  const nameParts = (username || "")
    .normalize("NFKC")
    .replace(/[^\p{L}\p{M}\s]/gu, "")
    .split(/\s+/u)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part.slice(0, 50));

  return {
    first_name: nameParts[0] || "Customer",
    last_name: nameParts[1] || "Customer",
  };
};

const nomodRequest = async <T>(path: string, init?: RequestInit): Promise<T> => {
  const apiKey = env.NOMOD_API_KEY.trim();
  if (!apiKey) throw new Error("Nomod checkout is not configured");

  let response: Response;
  try {
    response = await fetch(`${NOMOD_API_URL}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-API-KEY": apiKey,
        ...init?.headers,
      },
      signal: AbortSignal.timeout(15000),
    });
  } catch {
    throw new Error("Could not reach the Nomod payment service");
  }

  if (!response.ok) {
    let providerCode = "";
    let providerMessage = "";
    try {
      const body = (await response.json()) as {
        error?: { code?: unknown; message?: unknown };
        code?: unknown;
        message?: unknown;
      };
      const code = body.error?.code ?? body.code;
      const message = body.error?.message ?? body.message;
      if (typeof code === "string") providerCode = code.slice(0, 80);
      if (typeof message === "string") providerMessage = message.slice(0, 240);
    } catch {
      // Some upstream failures do not return a JSON body.
    }
    throw new Error(
      `Nomod payment service returned HTTP ${response.status}` +
        (providerCode ? ` (${providerCode})` : "") +
        (providerMessage ? `: ${providerMessage}` : ""),
    );
  }

  try {
    return (await response.json()) as T;
  } catch {
    throw new Error("Nomod payment service returned an invalid response");
  }
};

export const createNomodCheckout = (input: CreateNomodCheckoutInput) =>
  nomodRequest<NomodCheckoutSession>("/checkout", {
    method: "POST",
    body: JSON.stringify(input),
  });

export const getNomodCheckout = (checkoutId: string) =>
  nomodRequest<NomodCheckoutSession>(`/checkout/${encodeURIComponent(checkoutId)}`);
