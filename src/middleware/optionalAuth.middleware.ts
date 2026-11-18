// src/middleware/optionalAuth.middleware.ts
// Re-exports the centralized optionalAuthMiddleware so all entrypoints share identical
// stateful tokenVersion, active-status, and claim validation.
export { optionalAuthMiddleware } from "./auth.middleware";
