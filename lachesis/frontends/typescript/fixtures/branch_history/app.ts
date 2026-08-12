export function choose(flag: boolean): number {
  let result = 0;
  if (flag) {
    result = 1;
  } else {
    result = 2;
  }
  return result;
}
