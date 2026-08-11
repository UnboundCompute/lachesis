import { principalFor, normalizeTenant } from "@lachesis-fixture/core";

export function handleRequest(query: Record<string, string>) {
  // the cross-package call: this edge's callee lives in packages/core
  const principal = principalFor(query.id, query.tenant);
  if (!principal.tenant) {
    throw new Error("missing tenant");
  }
  return { principal, scope: normalizeTenant(query.scope) };
}
