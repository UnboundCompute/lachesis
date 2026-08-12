// Three handlers, one per case the planner has to get right.

import { Request } from "./router.js";
import {
  checkPermission, isPermitted, refreshPermissionCache, verifyRequiredFields,
  verifySignature,
} from "./guards.js";
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

// Checked, but not authorized: a shape validator answers "is this input well
// formed", never "is this caller allowed". It belongs in the evidence and must not
// clear the candidate.
export function renameRecord(req: Request): string {
  validateRecordId(req.recordId);
  store.deleteMany(req.recordId);
  return "renamed";
}

// The check answers a question and the handler acts on the answer. Nothing throws
// inside isPermitted, so this only suppresses because the result reaches a branch.
export function deleteRecord(req: Request): string {
  const allowed = isPermitted(req.userId, "delete-record");
  if (!allowed) {
    throw new Error("forbidden");
  }
  store.deleteMany(req.recordId);
  return "deleted";
}

// Calls something that reads like authorization and acts on nothing. This is the
// candidate a name-only rule suppresses and this one has to keep.
export function touchRecord(req: Request): string {
  refreshPermissionCache(req.userId);
  store.deleteMany(req.recordId);
  return "touched";
}

// Verifies an authentication object and acts on the answer: this one authorizes.
export function importRecord(req: Request): string {
  if (!verifySignature(req.userId, req.recordId)) {
    throw new Error("forbidden");
  }
  store.deleteMany(req.recordId);
  return "imported";
}

// Same family, same branch, different object: a required-fields check says nothing
// about who is calling, so this candidate has to stay on the queue.
export function submitRecord(req: Request): string {
  if (!verifyRequiredFields(req.recordId)) {
    throw new Error("bad request");
  }
  store.deleteMany(req.recordId);
  return "submitted";
}

function validateRecordId(recordId: string): void {
  if (!recordId) {
    throw new Error("bad request");
  }
}

// The requirement for this one is declared on the registration in index.ts, so
// nothing in this body calls a guard and no call-graph method can see it.
export function exportRecords(req: Request): string {
  const row = store.findOne(req.recordId);
  return row ? row : "none";
}
