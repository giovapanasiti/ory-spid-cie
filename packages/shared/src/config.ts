import { z } from "zod";

/** Parses process.env with a zod schema; errors list variable names only, never values. */
export function loadConfig<T extends z.ZodTypeAny>(schema: T, env: NodeJS.ProcessEnv = process.env): z.infer<T> {
  const res = schema.safeParse(env);
  if (!res.success) {
    const issues = res.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
    throw new Error(`Invalid configuration: ${issues}`);
  }
  return res.data;
}

export const secret = (min = 32) => z.string().min(min, `must be at least ${min} characters`);
export const url = () => z.string().url();
export const port = (def: number) => z.coerce.number().int().min(1).max(65535).default(def);
export const bool = (def: boolean) =>
  z
    .enum(["true", "false", "1", "0"])
    .default(def ? "true" : "false")
    .transform((v) => v === "true" || v === "1");
export const csv = () =>
  z
    .string()
    .default("")
    .transform((v) =>
      v
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    );
export { z };
