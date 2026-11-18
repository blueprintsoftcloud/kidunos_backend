// Storra E-Commerce Server
import express from "express";
import http from "http";
import { Server } from "socket.io";
import cors from "cors";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import path from "path";
import fs from "fs";

import { env } from "./config/env";
import "./config/prisma";
import { connectDB } from "./config/database";
import { errorHandler } from "./middleware/errorHandler.middleware";
import { generalLimiter } from "./middleware/rateLimit.middleware";
import { ensureCsrfCookie, csrfProtection } from "./middleware/csrf.middleware";
import { sanitizeRequest } from "./middleware/sanitize.middleware";
import { requestId } from "./middleware/requestId.middleware";
import initSocket from "./socket/socketManager";
import { initNotificationService } from "./services/notification.service";
import { initMaintenanceSchedule } from "./services/maintenance.service";
import { startHealthMonitor, stopHealthMonitor } from "./monitoring/healthMonitor";
import { ensureOtpCollectionsInitialized } from "./services/otp.service";
import {
  startEmailOutboxWorker,
  stopEmailOutboxWorker,
} from "./services/emailOutbox.service";

// Routes
import authRoutes from "./routes/auth.routes";
import adminRoutes from "./routes/admin.routes";
import superAdminRoutes from "./routes/superAdmin.routes";
import categoryRoutes from "./routes/category.routes";
import productRoutes from "./routes/product.routes";
import userRoutes from "./routes/user.routes";
import cartRoutes from "./routes/cart.routes";
import orderRoutes from "./routes/order.routes";
import addressRoutes from "./routes/address.routes";
import notificationRoutes from "./routes/notification.routes";
import couponRoutes from "./routes/coupon.routes";
import analyticsRoutes from "./routes/analytics.routes";
import staffRoutes from "./routes/staff.routes";
import auditLogRoutes from "./routes/auditLog.routes";
import settingsRoutes from "./routes/settings.routes";
import paymentLogRoutes from "./routes/paymentLog.routes";
import reviewRoutes from "./routes/review.routes";
import homeBannerRoutes from "./routes/homeBanner.routes";
import deliveryPartnerRoutes from "./routes/deliveryPartner.routes";
import staticPagesRoutes from "./routes/staticPages.routes";
import purchaseFeedbackRoutes from "./routes/purchaseFeedback.routes";
import { getSitemap, getRobotsTxt } from "./controllers/seo.controller";
import { serveDynamicHtml, getFaviconUrl } from "./utils/htmlRenderer";


const ALLOWED_ORIGINS = env.ALLOWED_ORIGINS
  .split(",")
  .map((o) => o.trim().replace(/\/+$/, ""))
  .filter(Boolean);

export const createApp = () => {
  const app = express();
  const server = http.createServer(app);

  // ── Request ID ────────────────────────────────────────────────────────────────
  // First middleware in the chain so every log line for this request — including
  // ones emitted by middleware that runs before routing — carries a correlation id.
  app.use(requestId);

  app.get("/health", (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });

  // ── Security Headers ─────────────────────────────────────────────────────────
  app.use(
    helmet({
      contentSecurityPolicy: false,
      referrerPolicy: { policy: "strict-origin-when-cross-origin" },
      crossOriginResourcePolicy: { policy: "cross-origin" },
      crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
    }),
  );

  // ── CORS ──────────────────────────────────────────────────────────────────────
  app.use(
    cors({
      origin: (origin, callback) => {
        // Allow requests with no origin (server-to-server webhooks like Razorpay, curl)
        if (!origin) return callback(null, true);
        if (ALLOWED_ORIGINS.includes(origin.replace(/\/+$/, ""))) {
          return callback(null, true);
        }
        // Omit CORS response headers for disallowed origins rather than throwing
        // 500 before route/CSRF middleware; mutating `/api/*` calls continue into
        // `csrfProtection` and receive a deterministic 403 CSRF_ORIGIN_INVALID.
        return callback(null, false);
      },
      credentials: true,
    }),
  );

  // ── Core Middleware ────────────────────────────────────────────────────────────
  // Configurable reverse-proxy hop count (default 1; update TRUST_PROXY_HOPS once
  // staging/prod Nginx/Cloudflare header topology is confirmed).
  app.set("trust proxy", env.TRUST_PROXY_HOPS);
  app.use(
    express.json({
      verify: (req: any, _res, buf) => {
        req.rawBody = buf;
      },
    }),
  );
  app.use(cookieParser());
  app.use(ensureCsrfCookie);

  // ── Request Hardening ────────────────────────────────────────────────────────
  // Strips Mongo operator keys ($ne, $where, ...) from body/query/params, then
  // enforces Origin/Referer allowlist + double-submit CSRF on all mutating /api routes
  // (Razorpay server-to-server webhook is strictly exempted).
  app.use(sanitizeRequest);
  app.use("/api", csrfProtection);

  // ── General Rate Limiter ──────────────────────────────────────────────────────
  app.use("/api", generalLimiter);

  // ── Static Uploads ────────────────────────────────────────────────────────────
  app.use("/uploads", express.static(path.join(__dirname, "uploads")));

  // ── Socket.IO ─────────────────────────────────────────────────────────────────
  const io = new Server(server, {
    cors: {
      origin: ALLOWED_ORIGINS,
      credentials: true,
    },
    transports: ["polling", "websocket"],
  });

  const stopSocketRecheck = initSocket(io);
  initNotificationService(io);
  app.set("socketio", io);

  // ── API Routes ────────────────────────────────────────────────────────────────
  app.use("/api/auth", authRoutes);
  app.use("/api/admin", adminRoutes);
  app.use("/api/super-admin", superAdminRoutes);
  app.use("/api/category", categoryRoutes);
  app.use("/api/product", productRoutes);
  app.use("/api/user", userRoutes);
  app.use("/api/cart", cartRoutes);
  app.use("/api/order", orderRoutes);
  app.use("/api/address", addressRoutes);
  app.use("/api/notifications", notificationRoutes);
  app.use("/api/coupon", couponRoutes);
  app.use("/api/analytics", analyticsRoutes);
  app.use("/api/staff", staffRoutes);
  app.use("/api/audit-logs", auditLogRoutes);
  app.use("/api/settings", settingsRoutes);
  app.use("/api/payment-logs", paymentLogRoutes);
  app.use("/api/reviews", reviewRoutes);
  app.use("/api/home-banners", homeBannerRoutes);
  app.use("/api/delivery-partners", deliveryPartnerRoutes);
  app.use("/api/pages", staticPagesRoutes);
  app.use("/api/purchase-feedback", purchaseFeedbackRoutes);

  // ── SEO: sitemap.xml / robots.txt / favicon ──────────────────────────────────
  app.get("/sitemap.xml", getSitemap);
  app.get("/robots.txt", getRobotsTxt);
  app.get(["/favicon.ico", "/favicon.png"], async (req, res) => {
    try {
      const faviconUrl = await getFaviconUrl();
      if (faviconUrl && faviconUrl.startsWith("http")) {
        return res.redirect(302, faviconUrl);
      }
    } catch (e) {}
    res.status(404).end();
  });

  // ── Serve React Frontend ───────────────────────────────────────────────────
  const candidateStaticDirs = [
    path.join(__dirname, "../../client"),
    path.join(__dirname, "../client"),
    path.join(process.cwd(), "client"),
    path.join(process.cwd(), "dist/client"),
    path.join(process.cwd(), "backend/client"),
    path.join(process.cwd(), "../frontend/dist"),
    path.join(__dirname, "../../../frontend/dist"),
    path.join(__dirname, "../../frontend/dist"),
  ];
  for (const dir of candidateStaticDirs) {
    if (fs.existsSync(dir)) {
      app.use(
        express.static(dir, {
          index: false,
          maxAge: "1y",
          immutable: true,
        }),
      );
    }
  }

  // ── React Router Catch-all (Dynamic Branding & SEO Injection) ──────────────
  app.get("*splat", (req, res) => {
    serveDynamicHtml(req, res);
  });

  // ── Error Handler ─────────────────────────────────────────────────────────────
  app.use(errorHandler);

  return { app, server, io, stopSocketRecheck };
};

const { app, server, io, stopSocketRecheck } = createApp();
export { app, server, io };

if (env.NODE_ENV !== "test") {
  process.on("uncaughtException", (err) => {
    console.log("❌ UNCAUGHT EXCEPTION:", err?.message || err);
    console.error("UNCAUGHT EXCEPTION:", err);
    process.exit(1);
  });

  process.on("unhandledRejection", (reason) => {
    console.log("❌ UNHANDLED REJECTION:", reason);
    console.error("UNHANDLED REJECTION:", reason);
    process.exit(1);
  });

  const PORT = process.env.PORT || env.PORT || 5000;
  server.on("error", (err: any) => {
    console.log(`❌ Server listen error on port ${PORT}:`, err?.message || err);
    process.exit(1);
  });
  server.listen(PORT, () => {
    console.log(`Server running on PORT ${PORT}`);
  });

  connectDB()
    .then(async () => {
      console.log("MongoDB connected.");
      await ensureOtpCollectionsInitialized();
      initMaintenanceSchedule();
      startHealthMonitor();
      startEmailOutboxWorker();
    })
    .catch((error) => {
      console.log("❌ Critical startup error connecting to MongoDB:", error?.message || error);
      console.error("Critical startup error:", error);
      process.exit(1);
    });

  let isShuttingDown = false;
  const gracefulShutdown = async (signal: string) => {
    if (isShuttingDown) return;
    isShuttingDown = true;
    console.log(`${signal} received — shutting down gracefully...`);
    try {
      stopHealthMonitor();
      await stopEmailOutboxWorker();
      stopSocketRecheck();
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(0), 10_000).unref();
    } catch (err) {
      console.error("Error during graceful shutdown:", err);
      process.exit(1);
    }
  };

  process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
  process.on("SIGINT", () => gracefulShutdown("SIGINT"));
}

