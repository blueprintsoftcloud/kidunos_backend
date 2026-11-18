import mongoose from "mongoose";

const INR_TO_AED = 0.039;

const toAedRetailPrice = (value: unknown): number | undefined => {
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
  return Math.round(value * INR_TO_AED);
};

const convertPricedCollection = async (
  collectionName: string,
  fields: string[],
  fixedCouponAmountsOnly = false,
) => {
  const collection = mongoose.connection.db!.collection(collectionName);
  for await (const document of collection.find({ currency: { $ne: "AED" } })) {
    if (document.currency && document.currency !== "INR") {
      throw new Error(`Unexpected currency "${document.currency}" in ${collectionName}`);
    }

    const values: Record<string, unknown> = { currency: "AED" };
    for (const field of fields) {
      if (fixedCouponAmountsOnly && field === "discountValue" && document.discountType !== "FLAT") continue;
      const converted = toAedRetailPrice(document[field]);
      if (converted !== undefined) values[field] = converted;
    }
    await collection.updateOne(
      { _id: document._id, currency: { $ne: "AED" } },
      { $set: values },
    );
  }
};

export async function up(): Promise<void> {
  await convertPricedCollection("products", ["price", "purchasePrice"]);
  await convertPricedCollection("productvariants", ["priceOverride", "purchasePriceOverride"]);
  await convertPricedCollection("coupons", ["minOrderAmount", "discountValue"], true);

  const db = mongoose.connection.db!;
  await db.collection("orders").updateMany(
    { currency: { $exists: false } },
    { $set: { currency: "INR" } },
  );
  await db.collection("paymentlogs").updateMany(
    { currency: { $exists: false } },
    { $set: { currency: "INR" } },
  );
  await db.collection("appsettings").updateOne(
    { key: "SHIPPING_UAE_FLAT_RATE_AED" },
    { $setOnInsert: { key: "SHIPPING_UAE_FLAT_RATE_AED", value: "15" } },
    { upsert: true },
  );
  await db.collection("appsettings").deleteMany({
    key: {
      $in: [
        "SHIPPING_SAME_STATE_PER_KM",
        "SHIPPING_SAME_STATE_FREE_KM",
        "SHIPPING_NO_LOCATION_FLAT",
        "SHIPPING_STATE_RATES",
        "SHIPPING_DISTRICT_RATES",
        "SHIPPING_CALCULATE_QR",
      ],
    },
  });
}
