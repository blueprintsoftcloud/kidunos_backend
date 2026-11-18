import type { Express } from "express";
import request from "supertest";

let ipCounter = 10;

export const nextTestIp = (): string => {
  ipCounter += 1;
  const octet3 = Math.floor(ipCounter / 250);
  const octet4 = (ipCounter % 250) + 1;
  return `10.20.${octet3}.${octet4}`;
};

export interface ParsedSetCookie {
  value: string;
  raw: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: string | null;
  path: string | null;
  maxAge: string | null;
}

export const parseSetCookies = (
  headers: string | string[] | undefined,
): Record<string, ParsedSetCookie> => {
  const arr = Array.isArray(headers) ? headers : headers ? [headers] : [];
  const result: Record<string, ParsedSetCookie> = {};

  for (const rawCookie of arr) {
    const parts = rawCookie.split(";").map((p) => p.trim());
    const [nameVal, ...attrs] = parts;
    const eqIdx = nameVal.indexOf("=");
    if (eqIdx === -1) continue;
    const name = nameVal.slice(0, eqIdx).trim();
    const value = decodeURIComponent(nameVal.slice(eqIdx + 1).trim());

    let httpOnly = false;
    let secure = false;
    let sameSite: string | null = null;
    let path: string | null = null;
    let maxAge: string | null = null;

    for (const attr of attrs) {
      const lower = attr.toLowerCase();
      if (lower === "httponly") httpOnly = true;
      else if (lower === "secure") secure = true;
      else if (lower.startsWith("samesite=")) sameSite = attr.slice(9).trim();
      else if (lower.startsWith("path=")) path = attr.slice(5).trim();
      else if (lower.startsWith("max-age=")) maxAge = attr.slice(8).trim();
    }

    result[name] = {
      value,
      raw: rawCookie,
      httpOnly,
      secure,
      sameSite,
      path,
      maxAge,
    };
  }
  return result;
};

export const bootstrapCsrfAgent = async (
  app: Express,
  origin = "http://localhost:5173",
) => {
  const agent = request.agent(app);
  const ip = nextTestIp();
  const res = await agent.get("/api/auth/csrf").set("X-Forwarded-For", ip);
  const csrfToken = res.body?.csrfToken as string;
  const cookies = parseSetCookies(res.headers["set-cookie"]);

  return {
    agent,
    ip,
    origin,
    csrfToken,
    cookies,
    res,
  };
};

