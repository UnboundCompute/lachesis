export interface Principal {
  id: string;
  tenant: string;
}

export function normalizeTenant(raw: string): string {
  return raw.trim().toLowerCase();
}

export function principalFor(id: string, tenant: string): Principal {
  return { id, tenant: normalizeTenant(tenant) };
}
