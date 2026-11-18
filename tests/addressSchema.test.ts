import { addressSchema } from "../src/schemas/address.schema";
import { Address } from "../src/models/mongoose";

describe("addressSchema", () => {
  it("accepts UAE addresses without a P.O. Box and defaults the country to UAE", () => {
    expect(
      addressSchema.parse({
        fullAddress: "Building 4, Street 12",
        city: "Ajman",
        state: "Ajman",
      }),
    ).toMatchObject({
      zipCode: "",
      country: "United Arab Emirates",
    });
  });

  it("persists an address without a P.O. Box", async () => {
    const address = new Address({
      userId: "507f1f77bcf86cd799439011",
      fullAddress: "Building 4, Street 12",
      city: "Ajman",
      state: "Ajman",
    });

    await expect(address.validate()).resolves.toBeUndefined();
    expect(address.zipCode).toBe("");
    expect(address.country).toBe("United Arab Emirates");
  });
});
