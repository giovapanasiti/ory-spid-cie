/** Internal levels of assurance (identity proofing + authentication strength). */
export const LOA = {
  NONE: "urn:iam:loa:none",
  LOW: "urn:iam:loa:low",
  SUBSTANTIAL: "urn:iam:loa:substantial",
  HIGH: "urn:iam:loa:high",
} as const;
export type LoA = (typeof LOA)[keyof typeof LOA];

const RANK: Record<string, number> = { [LOA.NONE]: 0, [LOA.LOW]: 1, [LOA.SUBSTANTIAL]: 2, [LOA.HIGH]: 3 };

export function loaRank(l: string | undefined | null): number {
  return l ? (RANK[l] ?? -1) : -1;
}

export function isLoA(v: string): v is LoA {
  return v in RANK;
}

/** Strictest recognised LoA in an acr_values list. */
export function requestedLoA(acrValues: readonly string[] | undefined): LoA | undefined {
  let best: LoA | undefined;
  for (const v of acrValues ?? []) {
    if (isLoA(v) && loaRank(v) > loaRank(best)) best = v;
  }
  return best;
}

export function satisfies(actual: string | undefined, required: string | undefined): boolean {
  if (!required) return true;
  return loaRank(actual) >= loaRank(required) && loaRank(required) >= 0;
}

/** Federated providers handled by the broker. */
export const FEDERATED_PROVIDERS = ["spid", "cie"] as const;
export type FederatedProvider = (typeof FEDERATED_PROVIDERS)[number];
export const isFederated = (p: string | undefined): p is FederatedProvider =>
  !!p && (FEDERATED_PROVIDERS as readonly string[]).includes(p);
