export interface Runner<T> {
  run(value: T): T;
}

function Controller(path: string): ClassDecorator {
  return () => undefined;
}

abstract class BaseRunner {
  abstract run(value: string): string;
}

@Controller("/runner")
export class StringRunner extends BaseRunner implements Runner<string> {
  static label = "runner";

  static {
    StringRunner.label = StringRunner.label.trim();
  }

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

export const singleton = new Map<string, string>();
export let mutableState = 0;
mutableState = 1;

export const callbacks = { check: isString };

export function invokeComputed(
  action: "check",
  value: unknown,
): boolean {
  return callbacks[action](value);
}

export function schedule(value: unknown): void {
  setTimeout(() => isString(value), 0);
}

export async function loadRuntimeModule(specifier: string): Promise<unknown> {
  return import(specifier);
}

export const reflected = Reflect.get({ value: 1 }, "value");
export const proxied = new Proxy({ value: 1 }, {});
