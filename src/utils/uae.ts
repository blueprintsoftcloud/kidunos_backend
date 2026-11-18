export const UAE_EMIRATES = [
  "Abu Dhabi",
  "Ajman",
  "Dubai",
  "Fujairah",
  "Ras Al Khaimah",
  "Sharjah",
  "Umm Al Quwain",
] as const;

const emiratesByNormalizedName = new Map(
  UAE_EMIRATES.map((emirate) => [emirate.toLowerCase(), emirate]),
);

export const normalizeUaeEmirate = (value: string): string | null =>
  emiratesByNormalizedName.get(value.trim().toLowerCase()) ?? null;
