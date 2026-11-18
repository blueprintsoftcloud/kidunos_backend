import http from "http";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import request from "supertest";
import { Server as SocketIOServer } from "socket.io";
import { io as ioClient, type Socket as ClientSocket } from "socket.io-client";
import { createApp } from "../src/server";
import { env } from "../src/config/env";
import { generateToken, hashRefreshTokenValue } from "../src/config/tokens";
import { EmailOutbox, StaffProfile, User } from "../src/models/mongoose";
import { decryptOutboxPayload } from "../src/utils/otpCrypto";
import initSocket from "../src/socket/socketManager";
import {
  bootstrapCsrfAgent,
  nextTestIp,
  parseSetCookies,
} from "./helpers/httpHelper";
import { clearTestDb, startTestDb, stopTestDb } from "./helpers/testDb";

const connectSocketWithCookies = (
  port: number,
  jwtCookie: string,
): Promise<ClientSocket> =>
  new Promise((resolve, reject) => {
    const client = ioClient(`http://127.0.0.1:${port}`, {
      transports: ["websocket"],
      extraHeaders: {
        Cookie: `jwt=${jwtCookie}`,
        "X-Forwarded-For": "203.0.113.45",
      },
      reconnection: false,
    });
    const timer = setTimeout(() => {
      client.close();
      reject(new Error("Socket connection timeout"));
    }, 5000);
    client.on("connect", () => {
      clearTimeout(timer);
      resolve(client);
    });
    client.on("connect_error", (err) => {
      clearTimeout(timer);
      client.close();
      reject(err);
    });
  });

const waitForSocketDisconnect = (
  client: ClientSocket,
): Promise<{ reason: string; revokedReason?: string }> =>
  new Promise((resolve, reject) => {
    let revokedReason: string | undefined;
    const timer = setTimeout(() => {
      reject(new Error("Timed out waiting for socket disconnect"));
    }, 5000);

    client.on("session-revoked", (payload: { reason?: string }) => {
      revokedReason = payload?.reason;
    });
    client.on("disconnect", (reason) => {
      clearTimeout(timer);
      resolve({ reason, revokedReason });
    });
  });

describe("PR 1 — Versioned JWT/refresh hashes, rotation grace, legacy rejection & immediate/periodic Socket.IO revocation (#5, #6, #7)", () => {
  let appCtx: ReturnType<typeof createApp>;
  let appPort = 0;

  beforeAll(async () => {
    await startTestDb();
    appCtx = createApp();
    await new Promise<void>((resolve) => {
      appCtx.server.listen(0, "127.0.0.1", () => {
        const addr = appCtx.server.address();
        appPort = typeof addr === "object" && addr ? addr.port : 0;
        resolve();
      });
    });
  });

  afterEach(async () => {
    jest.restoreAllMocks();
    await clearTestDb();
  });

  afterAll(async () => {
    if (appCtx) {
      appCtx.stopSocketRecheck();
      await new Promise<void>((resolve) => appCtx.io.close(() => resolve()));
    }
    await stopTestDb();
  });

  // Helper to seed user + obtain versioned access/refresh cookies through real generateToken
  const issueSessionForUser = async (userId: string, role: string, email: string, tokenVersion = 0) => {
    let capturedJwt = "";
    let capturedRefresh = "";
    const fakeRes = {
      clearCookie() {
        return this;
      },
      cookie(name: string, value: string) {
        if (name === "jwt") capturedJwt = value;
        if (name === "refreshToken") capturedRefresh = value;
        return this;
      },
    } as unknown as Parameters<typeof generateToken>[1];

    await generateToken({ id: userId, email, role, tokenVersion }, fakeRes);
    return { jwtCookie: capturedJwt, refreshCookie: capturedRefresh };
  };

  // Test #5: Legacy JWTs (no tokenVersion) rejected everywhere
  it("rejects pre-PR-1 legacy JWTs lacking tokenVersion on protected API routes, /api/auth/status, /api/auth/refresh, and Socket.IO handshakes (#5)", async () => {
    const user = await User.create({
      username: "Legacy User",
      email: "legacy@storra.test",
      phone: "9830000001",
      role: "CUSTOMER",
      isActive: true,
      isVerified: true,
      tokenVersion: 0,
    });

    const legacyAccessJwt = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      env.JWT_SECRET,
      { expiresIn: "15m" },
    );
    const legacyRefreshJwt = jwt.sign(
      { id: user.id, tokenValue: "plain-raw-value", family: "fam-legacy" },
      env.REFRESH_TOKEN_SECRET,
      { expiresIn: "7d" },
    );

    // 1. Protected API endpoint (/api/user/profile)
    const protectedRes = await request(appCtx.app)
      .get("/api/user/profile")
      .set("Cookie", [`jwt=${legacyAccessJwt}`]);
    expect(protectedRes.status).toBe(401);
    expect(protectedRes.body.code).toBe("LEGACY_TOKEN");

    // 2. /api/auth/status
    const statusRes = await request(appCtx.app)
      .get("/api/auth/status")
      .set("Cookie", [`jwt=${legacyAccessJwt}`]);
    expect(statusRes.status).toBe(401);
    expect(statusRes.body.isLoggedIn).toBe(false);
    expect(statusRes.body.code).toBe("LEGACY_TOKEN");

    // 3. /api/auth/refresh (with CSRF + legacy refresh cookie)
    const { csrfToken, origin } = await bootstrapCsrfAgent(appCtx.app);
    const refreshRes = await request(appCtx.app)
      .post("/api/auth/refresh")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("Cookie", [`csrfToken=${csrfToken}`, `refreshToken=${legacyRefreshJwt}`]);
    expect(refreshRes.status).toBe(401);
    expect(refreshRes.body.code).toBe("LEGACY_TOKEN");

    // 4. Socket.IO handshake
    await expect(connectSocketWithCookies(appPort, legacyAccessJwt)).rejects.toThrow();
  });

  // Test #6: SHA-256 refresh token hashing + 15m same-family grace rotation + out-of-family / post-revocation rejection
  it("hashes refresh tokens at rest with SHA-256, supports same-family grace rotation, and blocks out-of-family or post-revocation replays (#6)", async () => {
    const user = await User.create({
      username: "Token User",
      email: "tokens@storra.test",
      phone: "9830000002",
      role: "CUSTOMER",
      isActive: true,
      isVerified: true,
      tokenVersion: 0,
    });

    const initial = await issueSessionForUser(user.id, user.role, user.email!, 0);
    const decodedInitial = jwt.verify(initial.refreshCookie, env.REFRESH_TOKEN_SECRET) as {
      tokenValue: string;
      family: string;
      tokenVersion: number;
    };
    expect(decodedInitial.tokenVersion).toBe(0);

    // Assert raw tokenValue is NOT stored in MongoDB — only 64-hex SHA-256 digest is stored
    const dbUserAfterLogin = await User.findById(user.id).lean();
    expect(dbUserAfterLogin?.refreshToken).toBe(hashRefreshTokenValue(decodedInitial.tokenValue));
    expect(dbUserAfterLogin?.refreshToken).toMatch(/^[a-f0-9]{64}$/);
    expect(dbUserAfterLogin?.refreshToken).not.toBe(decodedInitial.tokenValue);

    const { csrfToken, origin } = await bootstrapCsrfAgent(appCtx.app);

    // First rotation succeeds -> pushes first hash into previousRefreshTokens
    const rot1Res = await request(appCtx.app)
      .post("/api/auth/refresh")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("Cookie", [`csrfToken=${csrfToken}`, `refreshToken=${initial.refreshCookie}`]);
    expect(rot1Res.status).toBe(200);
    const rot1Cookies = parseSetCookies(rot1Res.headers["set-cookie"]);
    expect(rot1Cookies.jwt?.value).toBeTruthy();
    expect(rot1Cookies.refreshToken?.value).toBeTruthy();

    const dbUserAfterRot1 = await User.findById(user.id).lean();
    expect(dbUserAfterRot1?.previousRefreshTokens?.length).toBeGreaterThanOrEqual(1);
    expect(dbUserAfterRot1?.previousRefreshTokens?.[0]?.token).toBe(
      hashRefreshTokenValue(decodedInitial.tokenValue),
    );

    // Same-family concurrent grace replay with initial cookie still succeeds within 15m
    const graceRes = await request(appCtx.app)
      .post("/api/auth/refresh")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("Cookie", [`csrfToken=${csrfToken}`, `refreshToken=${initial.refreshCookie}`]);
    expect(graceRes.status).toBe(200);

    // Out-of-family token fails with 403 and clears cookies
    const forgedOtherFamily = jwt.sign(
      {
        id: user.id,
        tokenValue: "wrong-token-value",
        family: "different-family-id",
        tokenVersion: 0,
      },
      env.REFRESH_TOKEN_SECRET,
      { expiresIn: "7d" },
    );
    const outFamilyRes = await request(appCtx.app)
      .post("/api/auth/refresh")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("Cookie", [`csrfToken=${csrfToken}`, `refreshToken=${forgedOtherFamily}`]);
    expect(outFamilyRes.status).toBe(403);
    const cleared = parseSetCookies(outFamilyRes.headers["set-cookie"]);
    expect(cleared.refreshToken?.value).toBe("");

    // Bump tokenVersion (revocation) -> existing same-family token fails 403
    await User.findByIdAndUpdate(user.id, { $inc: { tokenVersion: 1 }, refreshToken: null, previousRefreshTokens: [], refreshTokenFamily: null });
    const postRevokeRes = await request(appCtx.app)
      .post("/api/auth/refresh")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrfToken)
      .set("Cookie", [`csrfToken=${csrfToken}`, `refreshToken=${rot1Cookies.refreshToken.value}`]);
    expect(postRevokeRes.status).toBe(403);
    expect(postRevokeRes.body.code).toBe("TOKEN_VERSION_MISMATCH");
  });

  // Test #7: Immediate & periodic Socket.IO + JWT revocation on all security events
  describe("Immediate & periodic revocation across logout, reset, email change, staff/user updates & deletes (#7)", () => {
    it("immediately revokes JWT + disconnects Socket.IO on logout, while blocking unauthenticated spoofed logout tokenVersion bumps", async () => {
      const user = await User.create({
        username: "Logout Customer",
        email: "logout@storra.test",
        phone: "9830000010",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      });

      const { jwtCookie, refreshCookie } = await issueSessionForUser(user.id, user.role, user.email!, 0);
      const client = await connectSocketWithCookies(appPort, jwtCookie);
      const disconnectWait = waitForSocketDisconnect(client);

      // First verify an unauthenticated caller WITHOUT signed jwt cannot force tokenVersion bump via tampered payload
      const { csrfToken, origin } = await bootstrapCsrfAgent(appCtx.app);
      const fakeUnsigned = `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${Buffer.from(JSON.stringify({ id: user.id })).toString("base64url")}.`;
      await request(appCtx.app)
        .post("/api/auth/logout")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${fakeUnsigned}`]);
      expect((await User.findById(user.id).lean())?.tokenVersion).toBe(0);

      // Now genuine logout with real signed JWT -> bumps tokenVersion + clears refresh + disconnects socket
      const logoutRes = await request(appCtx.app)
        .post("/api/auth/logout")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${jwtCookie}`, `refreshToken=${refreshCookie}`]);
      expect(logoutRes.status).toBe(200);

      const disconnected = await disconnectWait;
      expect(disconnected.revokedReason).toBe("LOGOUT");

      const updated = await User.findById(user.id).lean();
      expect(updated?.tokenVersion).toBe(1);
      expect(updated?.refreshToken).toBeNull();

      // Old JWT immediately fails protected HTTP route
      const meRes = await request(appCtx.app)
        .get("/api/user/profile")
        .set("Cookie", [`jwt=${jwtCookie}`]);
      expect(meRes.status).toBe(401);
      expect(meRes.body.code).toBe("TOKEN_VERSION_MISMATCH");

      client.close();
    });

    it("revokes old session & disconnects sockets on password reset and profile email change (setting emailVerifiedAt on verified email change)", async () => {
      const admin = await User.create({
        username: "Reset Admin",
        email: "reset.admin@storra.test",
        phone: "9830000011",
        password: await bcrypt.hash("OldPass@123", 10),
        role: "ADMIN",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      });

      const session1 = await issueSessionForUser(admin.id, admin.role, admin.email!, 0);
      const client1 = await connectSocketWithCookies(appPort, session1.jwtCookie);
      const wait1 = waitForSocketDisconnect(client1);

      const { csrfToken, origin } = await bootstrapCsrfAgent(appCtx.app);
      const forgotRes = await request(appCtx.app)
        .post("/api/auth/forgot-password")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .set("Cookie", [`csrfToken=${csrfToken}`])
        .send({ email: admin.email });
      expect(forgotRes.status).toBe(200);

      const resetOutbox = await EmailOutbox.findOne({
        challengeId: forgotRes.body.challengeId,
      }).lean();
      const resetOtp = decryptOutboxPayload(resetOutbox!.encryptedPayload!).variables.OTP;

      const verifyResetRes = await request(appCtx.app)
        .post("/api/auth/verify-reset-otp")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .set("Cookie", [`csrfToken=${csrfToken}`])
        .send({ email: admin.email, otp: resetOtp, challengeId: forgotRes.body.challengeId });
      expect(verifyResetRes.status).toBe(200);
      const resetToken = parseSetCookies(verifyResetRes.headers["set-cookie"]).reset_token.value;

      const resetRes = await request(appCtx.app)
        .post("/api/auth/reset-password")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .set("Cookie", [`csrfToken=${csrfToken}`, `reset_token=${resetToken}`])
        .send({ newPassword: "NewStrongPass@123" });
      expect(resetRes.status).toBe(200);

      // Single-use reset_token replay must be rejected
      const resetReplayRes = await request(appCtx.app)
        .post("/api/auth/reset-password")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .set("Cookie", [`csrfToken=${csrfToken}`, `reset_token=${resetToken}`])
        .send({ newPassword: "AnotherPass@123" });
      expect(resetReplayRes.status).toBe(401);

      const disc1 = await wait1;
      expect(disc1.revokedReason).toBe("PASSWORD_RESET");
      expect((await User.findById(admin.id).lean())?.tokenVersion).toBe(1);
      client1.close();

      // Re-login / session 2 at tokenVersion 1, then change email via request-update + verify-update -> stamps emailVerifiedAt & disconnects stale sockets
      const session2 = await issueSessionForUser(admin.id, admin.role, admin.email!, 1);
      const client2 = await connectSocketWithCookies(appPort, session2.jwtCookie);
      const wait2 = waitForSocketDisconnect(client2);

      const reqUpdateRes = await request(appCtx.app)
        .post("/api/user/profile/request-update")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${session2.jwtCookie}`])
        .send({ newEmail: "new.admin@storra.test", newUsername: "Updated Admin" });
      expect(reqUpdateRes.status).toBe(200);

      const updateOutbox = await EmailOutbox.findOne({
        challengeId: reqUpdateRes.body.challengeId,
      }).lean();
      const updateOtp = decryptOutboxPayload(updateOutbox!.encryptedPayload!).variables.OTP;

      const verifyUpdateRes = await request(appCtx.app)
        .post("/api/user/profile/verify-update")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${session2.jwtCookie}`])
        .send({ otp: updateOtp, challengeId: reqUpdateRes.body.challengeId });
      expect(verifyUpdateRes.status).toBe(200);

      const disc2 = await wait2;
      expect(disc2.revokedReason).toBe("EMAIL_UPDATED");

      const afterEmail = await User.findById(admin.id).lean();
      expect(afterEmail?.email).toBe("new.admin@storra.test");
      expect(afterEmail?.emailVerifiedAt).toBeTruthy();
      expect(afterEmail?.tokenVersion).toBe(2);

      // Session 2 token rejected; newly issued cookie from verifyUpdateRes works!
      const staleAttempt = await request(appCtx.app)
        .get("/api/admin/adminProfile")
        .set("Cookie", [`jwt=${session2.jwtCookie}`]);
      expect(staleAttempt.status).toBe(401);

      const newCookies = parseSetCookies(verifyUpdateRes.headers["set-cookie"]);
      const freshAttempt = await request(appCtx.app)
        .get("/api/admin/adminProfile")
        .set("Cookie", [`jwt=${newCookies.jwt.value}`]);
      expect(freshAttempt.status).toBe(200);
      client2.close();
    });

    it("revokes sessions & disconnects sockets on staff toggle deactivation, staff update, staff delete, admin user deactivation, and user deletion", async () => {
      const admin = await User.create({
        username: "Super Manager",
        email: "mgr@storra.test",
        phone: "9830000020",
        password: await bcrypt.hash("Pass@1234", 10),
        role: "ADMIN",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      });

      const staffUser = await User.create({
        username: "Staff Member",
        email: "staff.live@storra.test",
        phone: "9830000021",
        password: await bcrypt.hash("Staff@1234", 10),
        role: "STAFF",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      });
      const staffProfile = await StaffProfile.create({
        userId: staffUser._id,
        managedBy: admin._id,
        permissions: ["ORDER_VIEW"],
        isActive: true,
      });

      const customer = await User.create({
        username: "Store Customer",
        email: "cust.live@storra.test",
        phone: "9830000022",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      });

      const adminSession = await issueSessionForUser(admin.id, admin.role, admin.email!, 0);
      const { csrfToken, origin } = await bootstrapCsrfAgent(appCtx.app);

      // 1. Update staff password -> increments tokenVersion + disconnects staff socket
      let staffSession = await issueSessionForUser(staffUser.id, "STAFF", staffUser.email!, 0);
      let staffSock = await connectSocketWithCookies(appPort, staffSession.jwtCookie);
      let staffWait = waitForSocketDisconnect(staffSock);

      const patchStaffRes = await request(appCtx.app)
        .patch(`/api/staff/${staffProfile.id}`)
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${adminSession.jwtCookie}`])
        .send({ newPassword: "NewStaffPassword1" });
      expect(patchStaffRes.status).toBe(200);
      expect((await staffWait).revokedReason).toBe("STAFF_PASSWORD_UPDATED");
      staffSock.close();
      expect((await User.findById(staffUser.id).lean())?.tokenVersion).toBe(1);

      // 2. Toggle staff inactive -> increments tokenVersion + disconnects staff socket
      staffSession = await issueSessionForUser(staffUser.id, "STAFF", staffUser.email!, 1);
      staffSock = await connectSocketWithCookies(appPort, staffSession.jwtCookie);
      staffWait = waitForSocketDisconnect(staffSock);

      const toggleRes = await request(appCtx.app)
        .patch(`/api/staff/${staffProfile.id}/toggle`)
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${adminSession.jwtCookie}`]);
      expect(toggleRes.status).toBe(200);
      expect(toggleRes.body.isActive).toBe(false);
      expect((await staffWait).revokedReason).toBe("STAFF_DEACTIVATED");
      staffSock.close();

      // 3. Delete staff -> disconnects even after reactivation
      await StaffProfile.findByIdAndUpdate(staffProfile.id, { isActive: true });
      staffSession = await issueSessionForUser(staffUser.id, "STAFF", staffUser.email!, 2);
      staffSock = await connectSocketWithCookies(appPort, staffSession.jwtCookie);
      staffWait = waitForSocketDisconnect(staffSock);

      const delStaffRes = await request(appCtx.app)
        .delete(`/api/staff/${staffProfile.id}`)
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${adminSession.jwtCookie}`]);
      expect(delStaffRes.status).toBe(200);
      expect((await staffWait).revokedReason).toBe("STAFF_DELETED");
      staffSock.close();

      // 4. Admin deactivates customer -> revokes customer JWT & disconnects customer socket; then delete customer -> disconnects reactivated socket
      let custSession = await issueSessionForUser(customer.id, "CUSTOMER", customer.email!, 0);
      let custSock = await connectSocketWithCookies(appPort, custSession.jwtCookie);
      let custWait = waitForSocketDisconnect(custSock);

      const patchCustRes = await request(appCtx.app)
        .patch(`/api/admin/users/${customer.id}`)
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${adminSession.jwtCookie}`])
        .send({ isActive: false });
      expect(patchCustRes.status).toBe(200);
      expect((await custWait).revokedReason).toBe("USER_DEACTIVATED");
      custSock.close();

      // Reactivate directly and test deleteUser socket disconnect
      await User.findByIdAndUpdate(customer.id, { isActive: true, tokenVersion: 1 });
      custSession = await issueSessionForUser(customer.id, "CUSTOMER", customer.email!, 1);
      custSock = await connectSocketWithCookies(appPort, custSession.jwtCookie);
      custWait = waitForSocketDisconnect(custSock);

      const delCustRes = await request(appCtx.app)
        .delete(`/api/admin/users/${customer.id}`)
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `jwt=${adminSession.jwtCookie}`]);
      expect(delCustRes.status).toBe(200);
      expect((await custWait).revokedReason).toBe("USER_DELETED");
      custSock.close();
    });

    it("disconnects active sockets via periodic MongoDB sweep when DB state changes out-of-band", async () => {
      const user = await User.create({
        username: "Sweep Target",
        email: "sweep@storra.test",
        phone: "9830000030",
        role: "CUSTOMER",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      });

      const httpServer = http.createServer();
      const io = new SocketIOServer(httpServer, { transports: ["websocket"] });
      const stopRecheck = initSocket(io, { recheckIntervalMs: 80 });

      await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
      const port = (httpServer.address() as { port: number }).port;

      try {
        const session = await issueSessionForUser(user.id, user.role, user.email!, 0);
        const client = await connectSocketWithCookies(port, session.jwtCookie);
        const discPromise = waitForSocketDisconnect(client);

        // Mutate DB directly out-of-band (simulating another worker process deactivating or incrementing tokenVersion)
        await User.findByIdAndUpdate(user.id, { $inc: { tokenVersion: 1 } });

        const disc = await discPromise;
        expect(disc.revokedReason).toBe("TOKEN_VERSION_MISMATCH");
        client.close();
      } finally {
        stopRecheck();
        await new Promise<void>((resolve) => io.close(() => resolve()));
      }
    });

    it("blocks STAFF with inactive StaffProfile from protected routes, /api/auth/refresh, /api/auth/login, and Socket.IO even when User.tokenVersion still matches", async () => {
      const staffUser = await User.create({
        username: "Suspended Staff",
        email: "suspended.staff@storra.test",
        phone: "9830000040",
        password: await bcrypt.hash("StaffPass@123", 10),
        role: "STAFF",
        isActive: true,
        isVerified: true,
        tokenVersion: 0,
      });
      const staffProfile = await StaffProfile.create({
        userId: staffUser._id,
        managedBy: staffUser._id,
        permissions: ["ORDER_VIEW"],
        isActive: true,
      });

      const session = await issueSessionForUser(staffUser.id, "STAFF", staffUser.email!, 0);
      const { csrfToken, origin } = await bootstrapCsrfAgent(appCtx.app);

      // Works while StaffProfile.isActive === true
      const activeProfileRes = await request(appCtx.app)
        .get("/api/user/profile")
        .set("Cookie", [`jwt=${session.jwtCookie}`]);
      expect(activeProfileRes.status).toBe(200);

      // Disable ONLY StaffProfile (leave User.isActive=true and User.tokenVersion=0)
      await StaffProfile.findByIdAndUpdate(staffProfile.id, { isActive: false });

      // Protected route rejects & clears cookies
      const blockedProfileRes = await request(appCtx.app)
        .get("/api/user/profile")
        .set("Cookie", [`jwt=${session.jwtCookie}`]);
      expect(blockedProfileRes.status).toBe(401);
      expect(blockedProfileRes.body.code).toBe("ACCOUNT_DEACTIVATED");
      expect(parseSetCookies(blockedProfileRes.headers["set-cookie"]).jwt?.value).toBe("");

      // Refresh endpoint rejects & clears cookies
      const blockedRefreshRes = await request(appCtx.app)
        .post("/api/auth/refresh")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("Cookie", [`csrfToken=${csrfToken}`, `refreshToken=${session.refreshCookie}`]);
      expect(blockedRefreshRes.status).toBe(403);
      const cleared = parseSetCookies(blockedRefreshRes.headers["set-cookie"]);
      expect(cleared.jwt?.value).toBe("");
      expect(cleared.refreshToken?.value).toBe("");

      // Socket.IO handshake rejects
      await expect(connectSocketWithCookies(appPort, session.jwtCookie)).rejects.toThrow();

      // Password login rejects
      const blockedLoginRes = await request(appCtx.app)
        .post("/api/auth/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrfToken)
        .set("X-Forwarded-For", nextTestIp())
        .send({ email: "suspended.staff@storra.test", password: "StaffPass@123" });
      expect(blockedLoginRes.status).toBe(403);
    });
  });
});
