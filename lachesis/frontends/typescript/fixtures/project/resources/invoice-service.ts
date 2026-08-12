import { findById } from "../data/repository.js";
import { principalKey } from "../auth/principal.js";
import { StoreRecord } from "tiny-store";

export function getInvoice(invoiceId: string): StoreRecord | undefined {
  const tenant = principalKey();
  const record = findById(invoiceId);
  if (record && record.tenant === tenant) {
    return record;
  }
  return undefined;
}
