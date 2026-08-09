interface Emitter {
  on(event: string, callback: (value: string) => string): void;
  emit(event: string, value: string): void;
}

function handle(value: string): string {
  return value;
}

export async function asyncFlow(
  emitter: Emitter,
  pending: Promise<string>,
): Promise<string> {
  emitter.on("data", handle);
  emitter.emit("data", "payload");
  setTimeout(handle, 1);
  const value = await pending.then(handle);
  return value;
}
