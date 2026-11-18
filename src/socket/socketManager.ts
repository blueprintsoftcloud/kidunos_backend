import { Server, Socket } from "socket.io";
import jwt from "jsonwebtoken";
import proxyaddr from "proxy-addr";
import { env } from "../config/env";
import logger from "../utils/logger";
import {
  validateActiveSessionUser,
  validateSocketSessionsBatch,
  type DecodedSessionClaims,
} from "../services/session.service";

export const SOCKET_RECHECK_INTERVAL_MS = 30_000;

interface AuthSocket extends Socket {
  user?: {
    id: string;
    email: string;
    role: string;
    tokenVersion: number;
  };
  clientIp?: string;
}

export interface InitSocketOptions {
  /** Override periodic MongoDB session-revalidation cadence (defaults to 30 seconds). */
  recheckIntervalMs?: number;
}

// Engine.IO's own `socket.handshake.address` is read straight off the raw TCP
// connection (see engine.io's Socket#remoteAddress) — it has no concept of
// X-Forwarded-For, so behind a reverse proxy it always reports the proxy's own
// address, never the real client. `proxy-addr` is the same library Express's
// `app.set("trust proxy", ...)` uses internally (server.ts), so reading
// `env.TRUST_PROXY_HOPS` here keeps both in sync.
const trustHop = (_addr: string, i: number) => i < env.TRUST_PROXY_HOPS;

const resolveClientIp = (socket: Socket): string =>
  proxyaddr(socket.request, trustHop);

const extractCookieValue = (cookieHeader: string, key: string): string | undefined => {
  const pair = cookieHeader
    .split(";")
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${key}=`));
  if (!pair) return undefined;
  const raw = pair.slice(key.length + 1);
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
};

/**
 * Immediately disconnects every socket on this worker belonging to `userId`.
 */
export const disconnectUserSockets = (
  io: Server | undefined | null,
  userId: string,
  reason: string = "SESSION_REVOKED",
): void => {
  if (!io || !userId) return;
  io.in(userId).emit("session-revoked", { reason });
  io.in(userId).disconnectSockets(true);
  logger.info("Socket.IO disconnected user sockets", { userId, reason });
};

const initSocket = (io: Server, options: InitSocketOptions = {}): (() => void) => {
  const recheckIntervalMs = options.recheckIntervalMs ?? SOCKET_RECHECK_INTERVAL_MS;

  io.use(async (socket: AuthSocket, next) => {
    try {
      const cookieHeader = socket.handshake.headers?.cookie ?? "";
      const token =
        (typeof socket.handshake.auth?.token === "string" && socket.handshake.auth.token) ||
        extractCookieValue(cookieHeader, "jwt");

      if (!token) return next(new Error("Authentication error"));

      const decoded = jwt.verify(token, env.JWT_SECRET) as DecodedSessionClaims;
      const validation = await validateActiveSessionUser(decoded);
      if (!validation.valid) {
        logger.warn("Socket.IO handshake rejected", {
          code: validation.code,
          reason: validation.message,
        });
        return next(new Error("Authentication error"));
      }

      socket.user = {
        id: validation.user.id,
        email: validation.user.email,
        role: validation.user.role,
        tokenVersion: validation.user.tokenVersion,
      };
      next();
    } catch {
      next(new Error("Authentication error"));
    }
  });

  io.on("connection", (socket: AuthSocket) => {
    const user = socket.user!;
    socket.clientIp = resolveClientIp(socket);
    logger.info(`Socket connected: ${user.email || user.id} | Role: ${user.role} | IP: ${socket.clientIp}`);

    if (user.role === "ADMIN" || user.role === "SUPER_ADMIN") {
      socket.join("admin-room");
    }

    socket.join(user.id);

    socket.on("disconnect", (reason) => {
      logger.info(`Socket disconnected: ${user.email || user.id} | Reason: ${reason} | IP: ${socket.clientIp}`);
    });
  });

  // Cross-worker session revalidation fallback (Phusion Passenger / multi-process without Redis):
  // Periodically checks connected sockets against shared MongoDB state so revocations on
  // another worker disconnect sockets within at most one recheck interval (30s default).
  const revalidateSweep = async () => {
    const connected = Array.from(io.sockets.sockets.values()) as AuthSocket[];
    if (connected.length === 0) return;

    const entries = connected
      .filter((s) => s.connected && s.user)
      .map((s) => ({ socketId: s.id, claims: s.user as DecodedSessionClaims }));

    if (entries.length === 0) return;

    try {
      const validationMap = await validateSocketSessionsBatch(entries);
      for (const sock of connected) {
        const result = validationMap.get(sock.id);
        if (result && !result.valid) {
          logger.info("Socket.IO periodic recheck revoking stale connection", {
            userId: sock.user?.id,
            code: result.code,
          });
          sock.emit("session-revoked", { reason: result.code });
          sock.disconnect(true);
        }
      }
    } catch (err) {
      logger.warn("Socket.IO periodic revalidation check failed", err);
    }
  };

  let timer: ReturnType<typeof setInterval> | null = null;
  if (recheckIntervalMs > 0) {
    timer = setInterval(() => {
      void revalidateSweep();
    }, recheckIntervalMs);
    timer.unref();
  }

  return () => {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  };
};

export default initSocket;
