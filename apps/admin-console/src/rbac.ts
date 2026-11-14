/** Least-privilege permission model for the admin console. */
export type Permission =
  | "dashboard"
  | "users.read"
  | "users.attributes"
  | "sessions.revoke"
  | "roles.manage"
  | "clients.read"
  | "clients.write"
  | "federation.read"
  | "federation.write"
  | "audit.read";

const MATRIX: Record<string, Permission[]> = {
  viewer: ["dashboard", "users.read", "clients.read", "federation.read"],
  support: ["dashboard", "users.read", "users.attributes", "sessions.revoke"],
  "client-admin": ["dashboard", "clients.read", "clients.write"],
  "federation-admin": ["dashboard", "federation.read", "federation.write"],
  "security-auditor": ["dashboard", "users.read", "federation.read", "clients.read", "audit.read"],
  superadmin: ["dashboard", "users.read", "users.attributes", "sessions.revoke", "roles.manage", "clients.read", "clients.write", "federation.read", "federation.write", "audit.read"],
};

export function can(roles: string[], p: Permission): boolean {
  return roles.some((r) => MATRIX[r]?.includes(p));
}

export const ALL_ROLES = Object.keys(MATRIX);
