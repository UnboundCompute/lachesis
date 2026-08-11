declare const require: (specifier: string) => unknown;

class Mutable {
  run(): string { return "original"; }
}

export function dynamicBehavior(
  input: string,
  specifier: string,
  target: Record<string, unknown>,
  key: string,
): unknown[] {
  eval(input);
  const generated = new Function("value", input);
  const loaded = require(specifier);
  const reflected = Reflect.get(target, key);
  const proxied = new Proxy(target, {});
  target[key] = input;
  Mutable.prototype.run = generated as () => string;
  return [loaded, reflected, proxied, import(specifier)];
}

export function shadowed(
  eval: (value: string) => string,
  value: string,
): string {
  return eval(value);
}
