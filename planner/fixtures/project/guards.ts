// The three shapes an authorization-named call can take. Only the first two enforce
// anything, and telling them apart is the whole job of the suppression rule.

// Throws on failure, so calling it is enough: guard-shaped callee.
export function checkPermission(userId: string, permission: string): void {
  if (!userId || !permission) {
    throw new Error("forbidden");
  }
}

// Answers a question and enforces nothing on its own. It only guards where the
// caller branches on the answer.
export function isPermitted(userId: string, permission: string): boolean {
  return Boolean(userId) && permission.length > 0;
}

// Authorization-named, does no checking at all. A name is not a check, and this is
// the call the suppression rule has to refuse.
export function refreshPermissionCache(userId: string): number {
  return userId.length;
}
