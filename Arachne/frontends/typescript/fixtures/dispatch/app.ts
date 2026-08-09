interface Service {
  run(): string;
}

class First implements Service {
  run(): string { return "first"; }
}

class Second implements Service {
  run(): string { return "second"; }
}

function invoke(callback: () => string): string {
  return callback();
}

function action(): string {
  return "action";
}

export function dispatch(service: Service): string[] {
  const holder = { action };
  const key: "action" = "action";
  const bound = action.bind(null);
  return [
    service.run(),
    holder.action(),
    holder[key](),
    action.call(null),
    action.apply(null),
    bound(),
    invoke(action),
  ];
}

export const implementations = [new First(), new Second()];
