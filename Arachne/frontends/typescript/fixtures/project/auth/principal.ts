import { Principal, Session } from "../types.js";

// Touching a DOM global keeps `lib.dom.d.ts` in the program, so the graph carries
// a standard-library file alongside the application and dependency ones.
function decodeSession(): Session {
  const holder = document.getElementById("session");
  const raw = holder ? holder.title : document.cookie;
  const parts = raw.split(".");
  return { token: parts[0], tenant: parts[1] };
}

function resolvePrincipal(): Principal {
  const session = decodeSession();
  return { tenant: session.tenant, subject: session.token };
}

export function principalKey(): string {
  const principal = resolvePrincipal();
  return principal.tenant + "/" + principal.subject;
}
