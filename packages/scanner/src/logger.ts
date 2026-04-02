/**
 * Structured JSON Lines logger — zero dependencies.
 * Output: one JSON object per line to stdout/stderr.
 * Fields follow ECS (Elastic Common Schema) conventions:
 *   - level: debug | info | warn | error
 *   - time: ISO-8601 UTC (e.g. "2026-03-22T11:30:00.123Z")
 *   - msg: human-readable message
 *   - ...context: arbitrary key-value pairs
 */

type Level = "debug" | "info" | "warn" | "error";

const LEVEL_VALUE: Record<Level, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

function write(level: Level, msg: string, context?: Record<string, unknown>) {
  const minLevel = LEVEL_VALUE[(process.env.LOG_LEVEL as Level) ?? "info"] ?? 20;
  if (LEVEL_VALUE[level] < minLevel) return;

  const entry = {
    level,
    time: new Date().toISOString(),
    msg,
    ...context,
  };

  const line = JSON.stringify(entry);
  process.stderr.write(line + "\n");
}

export const log = {
  debug: (msg: string, ctx?: Record<string, unknown>) => write("debug", msg, ctx),
  info: (msg: string, ctx?: Record<string, unknown>) => write("info", msg, ctx),
  warn: (msg: string, ctx?: Record<string, unknown>) => write("warn", msg, ctx),
  error: (msg: string, ctx?: Record<string, unknown>) => write("error", msg, ctx),

  /** Create a child logger with preset context fields */
  child: (defaults: Record<string, unknown>) => ({
    debug: (msg: string, ctx?: Record<string, unknown>) => write("debug", msg, { ...defaults, ...ctx }),
    info: (msg: string, ctx?: Record<string, unknown>) => write("info", msg, { ...defaults, ...ctx }),
    warn: (msg: string, ctx?: Record<string, unknown>) => write("warn", msg, { ...defaults, ...ctx }),
    error: (msg: string, ctx?: Record<string, unknown>) => write("error", msg, { ...defaults, ...ctx }),
  }),
};
