import {
  createNomodCheckout,
  getNomodCheckout,
  getNomodCustomerName,
} from "../src/services/nomod.service";

describe("Nomod checkout service", () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("creates provider-safe customer names from a username", () => {
    expect(getNomodCustomerName("Amina O'Neil, FZ-LLC 123")).toEqual({
      first_name: "Amina",
      last_name: "ONeil",
    });
    expect(getNomodCustomerName("!!!")).toEqual({
      first_name: "Customer",
      last_name: "Customer",
    });
  });

  it("creates an AED checkout using the backend API key", async () => {
    const checkout = {
      id: "checkout_123",
      url: "https://checkout.nomod.com/checkout_123",
      status: "pending",
      amount: 1500,
      currency: "AED",
      reference_id: "order_123",
    };
    const fetchMock = jest.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(checkout), { status: 201 }),
    );
    const input = {
      reference_id: "order_123",
      amount: "15.00",
      currency: "AED" as const,
      items: [{ item_id: "item_1", name: "Product", quantity: 1, unit_amount: "15.00" }],
      success_url: "https://store.example/order-success",
      failure_url: "https://store.example/order-success",
      cancelled_url: "https://store.example/order-success",
    };

    await expect(createNomodCheckout(input)).resolves.toEqual(checkout);

    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toBe("https://api.nomod.com/v1/checkout");
    expect(options?.method).toBe("POST");
    expect(new Headers(options?.headers).get("X-API-KEY")).toBe("test_nomod_api_key");
    expect(JSON.parse(String(options?.body))).toEqual(input);
  });

  it("encodes checkout IDs when retrieving a session", async () => {
    const checkout = {
      id: "checkout/123",
      url: "https://checkout.nomod.com/checkout_123",
      status: "paid",
      amount: 1500,
      currency: "AED",
      reference_id: "order_123",
    };
    const fetchMock = jest.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(checkout), { status: 200 }),
    );

    await expect(getNomodCheckout("checkout/123")).resolves.toEqual(checkout);
    expect(fetchMock.mock.calls[0][0]).toBe("https://api.nomod.com/v1/checkout/checkout%2F123");
  });

  it("surfaces safe upstream error details without retaining the raw response body", async () => {
    jest.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          error: {
            code: "not_authenticated",
            message: "Please use your API Key to authenticate",
          },
        }),
        { status: 401 },
      ),
    );

    await expect(getNomodCheckout("checkout_123")).rejects.toThrow(
      "Nomod payment service returned HTTP 401 (not_authenticated): Please use your API Key to authenticate",
    );
  });
});
