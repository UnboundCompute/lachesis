export interface Runner<T> {
  run(value: T): T;
}

export class StringRunner implements Runner<string> {
  run(value: string): string {
    return value.trim();
  }
}

export function isString(value: unknown): value is string {
  return typeof value === "string";
}

export function identity<T>(value: T): T {
  return value;
}

export function execute(
  value: string | number,
  runner: Runner<string>,
): string {
  if (isString(value)) {
    return runner.run(identity(value));
  }
  return String(value);
}

