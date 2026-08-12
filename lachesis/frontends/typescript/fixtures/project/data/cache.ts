interface CacheEntry {
  hit: boolean;
}

const entries: Map<string, CacheEntry> = new Map();

// A property write through a parameter — this is what lifts `heap_identity` and
// `effects` off "none" for the composed project.
function markHit(entry: CacheEntry): void {
  entry.hit = true;
}

export function remember(key: string, hit: boolean): void {
  const entry: CacheEntry = { hit: false };
  if (hit) {
    markHit(entry);
  }
  entries.set(key, entry);
}

function recall(key: string): boolean {
  const entry = entries.get(key);
  return entry ? entry.hit : false;
}
