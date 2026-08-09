export function controlFlow(value: number, items: number[]): number {
  let total = 0;
  if (value > 0) {
    total = value;
  } else {
    total = -value;
  }

  for (const item of items) {
    if (item === 0) continue;
    if (item < 0) break;
    total += item;
  }

  switch (value) {
    case 1:
      total += 10;
      break;
    default:
      total += 20;
  }

  try {
    if (value === 42) throw new Error("answer");
  } catch {
    total = -1;
  } finally {
    total += 1;
  }

  return total;
  total = 999;
}
