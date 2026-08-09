export function aliases(): object {
  const a = {};
  const b = a;
  b.secret = { value: 1 };
  return a.secret;
}

function make(): object {
  return {};
}

export function separateContexts(): object[] {
  const first = make();
  const second = make();
  return [first, second];
}

function update(user: { admin: boolean }): void {
  user.admin = true;
}

export function callerMutation(): boolean {
  const account = { admin: false };
  update(account);
  return account.admin;
}
