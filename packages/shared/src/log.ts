import { pino, type Logger } from "pino";

/** Paths that must never be logged. */
export const REDACT_PATHS = [
  "req.headers.authorization",
  "req.headers.cookie",
  'res.headers["set-cookie"]',
  "*.access_token",
  "*.refresh_token",
  "*.id_token",
  "*.client_secret",
  "*.code",
  "*.password",
  "*.private_key_pem",
];

export function createLogger(service: string, level = process.env.LOG_LEVEL ?? "info"): Logger {
  return pino({
    level,
    base: { service },
    redact: { paths: REDACT_PATHS, censor: "[REDACTED]" },
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: { level: (label) => ({ level: label }) },
  });
}

export const fastifyLoggerOptions = (service: string) => ({
  level: process.env.LOG_LEVEL ?? "info",
  base: { service },
  redact: { paths: REDACT_PATHS, censor: "[REDACTED]" },
  timestamp: pino.stdTimeFunctions.isoTime,
  formatters: { level: (label: string) => ({ level: label }) },
});
export type { Logger };
