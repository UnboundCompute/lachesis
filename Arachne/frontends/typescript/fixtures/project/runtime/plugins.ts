// One dynamic behaviour, so the graph carries a `dynamic-behavior` node and the
// frontier of statically unresolvable control is visible rather than silent.
function loadPlugin(body: string): (value: string) => string {
  const factory = new Function("value", body);
  return factory as (value: string) => string;
}
