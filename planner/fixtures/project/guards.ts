// The guard the recognition layer should find by name and by shape.

export function checkPermission(userId: string, permission: string): void {
  if (!userId || !permission) {
    throw new Error("forbidden");
  }
}
