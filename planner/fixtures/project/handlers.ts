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

// Delegation, not effect. Both callees read like a sink name and neither performs
// an operation: the real ones are one hop down and are candidates there. A sink
// catalog that matches these manufactures a duplicate candidate whose named effect
// is a function call.
export function cleanupRecord(req: Request): string {
  renameRecordRow(req.recordId);
  return executeRecordCleanup(req.recordId);
}

function renameRecordRow(recordId: string): string | undefined {
  return store.findOne(recordId);
}

function executeRecordCleanup(recordId: string): string {
  store.deleteMany(recordId);
  store.executeStatement("delete from records");
  return "cleaned";
}

// The guard is real, is authorization, and is inside a branch the effect is not
// in: a caller with no `req.userId` skips the check entirely and still deletes.
// Suppressing this is the missed bug A2 exists to prevent.
export function pruneRecord(req: Request): string {
  if (req.userId) {
    checkPermission(req.userId, "prune-record");
  }
  store.deleteMany(req.recordId);
  return "pruned";
}

// The guard is on the path and runs after the effect it would have to protect.
// Order is the other half of dominance, and this one fails it.
export function sealRecord(req: Request): string {
  const sealed = sealRecordRow(req.recordId);
  checkPermission(req.userId, "seal-record");
  return sealed;
}

function sealRecordRow(recordId: string): string {
  store.deleteMany(recordId);
  return "sealed";
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
