export function normalizeId(raw: string): string {
  const trimmed = raw.trim();
  return trimmed.toLowerCase();
}

function isBlank(value: string): boolean {
  return value.length === 0;
}
