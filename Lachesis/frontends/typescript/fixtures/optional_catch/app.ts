export function parseOptional(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

export function continuesAfterCatch(value: string): string {
  return value.trim();
}
