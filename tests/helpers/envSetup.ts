import path from "path";

// Keep MongoDB Memory Server binaries inside gitignored node_modules/.cache so sandboxed
// Jest runs can execute cached mongod.exe without accessing user profile directories outside workspace.
process.env.MONGOMS_DOWNLOAD_DIR = path.resolve(
  __dirname,
  "../../node_modules/.cache/mongodb-memory-server",
);

// Populates deterministic test environment variables before any application module imports `src/config/env.ts`.
process.env.NODE_ENV = "test";
process.env.PORT = "0";
process.env.MONGO_URL = "mongodb://127.0.0.1:27017/storra_pr1_test";
process.env.JWT_SECRET = "test_jwt_secret_key_for_pr1_suite_minimum_64_hex_chars_0123456789abcdef";
process.env.REFRESH_TOKEN_SECRET =
  "test_refresh_secret_key_distinct_for_pr1_suite_64_chars_fedcba9876543210";
process.env.OTP_HMAC_SECRET =
  "test_otp_hmac_secret_key_for_pr1_suite_minimum_64_chars_0011223344556677";
process.env.OUTBOX_ENC_KEY =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
process.env.RAZORPAY_KEY_ID = "rzp_test_key_id";
process.env.RAZORPAY_KEY_SECRET = "rzp_test_key_secret_123456";
process.env.RAZORPAY_WEBHOOK_SECRET = "rzp_test_webhook_secret_abcdef";
process.env.NOMOD_API_KEY = "test_nomod_api_key";
process.env.ALLOWED_ORIGINS = "http://localhost:5173,https://shop.storra.test";
process.env.TRUST_PROXY_HOPS = "1";
process.env.MSG91_AUTH_KEY = "test_msg91_auth_key_value";
process.env.MSG91_TOKEN_AUTH = "test_msg91_token_auth";
process.env.MSG91_WIDGET_ID = "test_msg91_widget_id";
process.env.MSG91_EMAIL_DOMAIN = "mail.storra.test";
process.env.MSG91_EMAIL_FROM = "noreply@mail.storra.test";
process.env.MSG91_EMAIL_FROM_NAME = "Storra Test";
process.env.MSG91_TEMPLATE_OTP = "tmpl_otp_test";
process.env.MSG91_TEMPLATE_ORDER_CONFIRMATION = "tmpl_order_conf_test";
process.env.MSG91_TEMPLATE_ORDER_STATUS = "tmpl_order_status_test";
process.env.MSG91_TEMPLATE_HEALTH_ALERT = "tmpl_health_alert_test";
