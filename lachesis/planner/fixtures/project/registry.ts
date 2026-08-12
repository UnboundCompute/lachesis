// Method registration through an object literal. Nothing here is a route and no
// callback is passed positionally, so the two older recognitions see none of it.

import { checkPermission } from "./guards.js";
import { store } from "./store.js";

export const methods = {
  register(handlers: Record<string, unknown>): void {
    void handlers;
  },
};

// Declared elsewhere and registered by shorthand.
export function dropRecord(recordId: string): number {
  checkPermission(recordId, "drop-record");
  return store.deleteMany(recordId);
}

methods.register({
  dropRecord,
  // Declared inline, and guarded by nothing: this is the one that has to reach
  // the queue rather than never being scanned at all.
  wipeRecord(recordId: string): number {
    return store.deleteMany(recordId);
  },
});
