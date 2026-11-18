/** @type {import('jest').Config} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  roots: ["<rootDir>/tests"],
  testMatch: ["**/*.test.ts"],
  setupFiles: ["<rootDir>/tests/helpers/envSetup.ts"],
  testTimeout: 60000,
  clearMocks: false,
  restoreMocks: true,
  moduleNameMapper: {
    "^isomorphic-dompurify$": "<rootDir>/tests/helpers/dompurifyMock.ts",
  },
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        tsconfig: "<rootDir>/tsconfig.test.json",
      },
    ],
  },
};
