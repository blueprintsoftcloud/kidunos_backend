export interface OperationalMongoUrlResolution {
  uri: string;
  ignoredConflictingDatabaseUrl: boolean;
  missingDueToDatabaseUrlOnly: boolean;
}

/**
 * Resolves the canonical operational MongoDB connection URI cleanly using `MONGO_URL`.
 *
 * Matches runtime `config/database.ts` (`MONGO_URL` only) so maintenance scripts can
 * never silently fall back to an unrelated `DATABASE_URL` when `MONGO_URL` is unset or empty.
 * Never embeds connection strings or credentials in diagnostics.
 */
export const resolveOperationalMongoUrlDetails = (
  envObj: NodeJS.ProcessEnv = process.env,
): OperationalMongoUrlResolution => {
  const mongoUrl = (envObj.MONGO_URL ?? "").trim();
  const databaseUrl = (envObj.DATABASE_URL ?? "").trim();

  if (!mongoUrl) {
    return {
      uri: "",
      ignoredConflictingDatabaseUrl: false,
      missingDueToDatabaseUrlOnly: Boolean(databaseUrl),
    };
  }

  return {
    uri: mongoUrl,
    ignoredConflictingDatabaseUrl: Boolean(databaseUrl && databaseUrl !== mongoUrl),
    missingDueToDatabaseUrlOnly: false,
  };
};

export const resolveOperationalMongoUrl = (
  envObj: NodeJS.ProcessEnv = process.env,
): string => resolveOperationalMongoUrlDetails(envObj).uri;

export const requireOperationalMongoUrl = (
  scriptLabel: string,
  envObj: NodeJS.ProcessEnv = process.env,
  onWarning?: (message: string) => void,
): string => {
  const resolved = resolveOperationalMongoUrlDetails(envObj);
  if (!resolved.uri) {
    if (resolved.missingDueToDatabaseUrlOnly) {
      throw new Error(
        `ERROR: MONGO_URL must be set to run ${scriptLabel} (implicit DATABASE_URL fallback is disabled to match runtime database selection).`,
      );
    }
    throw new Error(`ERROR: MONGO_URL must be set to run ${scriptLabel}.`);
  }

  if (resolved.ignoredConflictingDatabaseUrl) {
    const warnMsg = `Warning: DATABASE_URL is also set and differs from MONGO_URL; ignoring DATABASE_URL and using canonical MONGO_URL for ${scriptLabel}.`;
    if (onWarning) {
      onWarning(warnMsg);
    } else {
      console.warn(warnMsg);
    }
  }

  return resolved.uri;
};

