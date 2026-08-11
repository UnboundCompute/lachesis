import { findById } from "../data/repository.js";
import { StoreRecord } from "tiny-store";

// Deliberately unguarded: the tenant is never consulted before the lookup. Its
// sibling `getInvoice` reaches the same repository call behind an authorization
// accessor, which is what makes this a differential rather than a lone rule hit.
export function getDocument(documentId: string): StoreRecord | undefined {
  return findById(documentId);
}
