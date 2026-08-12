import { openStore, StoreRecord } from "tiny-store";

const store = openStore();

export function findById(key: string): StoreRecord | undefined {
  return store.read(key);
}

function save(value: StoreRecord): void {
  store.write(value.id, value);
}
