// Three handlers, one per case the planner has to get right.

import { Request } from "./router.js";
import { checkPermission } from "./guards.js";
import { store } from "./store.js";

// Guarded at the registered wrapper, effect one hop down. Read from the
// implementation alone this looks unguarded, which is the false positive
// entrypoint anchoring exists to kill.
export function archiveRecord(req: Request): string {
  checkPermission(req.userId, "archive-record");
  return archiveRecordRow(req.recordId);
}

// The implementation. It carries no guard of its own on purpose.
export function archiveRecordRow(recordId: string): string {
  const row = store.findOne(recordId);
  return row ? "archived" : "missing";
}

// No guard anywhere on the path: the case that belongs on the queue.
export function purgeRecord(req: Request): string {
  store.deleteMany(req.recordId);
  return "purged";
}

// The requirement for this one is declared on the registration in index.ts, so
// nothing in this body calls a guard and no call-graph method can see it.
export function exportRecords(req: Request): string {
  const row = store.findOne(req.recordId);
  return row ? row : "none";
}
