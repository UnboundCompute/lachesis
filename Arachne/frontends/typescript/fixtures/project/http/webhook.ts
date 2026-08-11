import { getDocument } from "../resources/document-service.js";
import { getInvoice } from "../resources/invoice-service.js";
import { normalizeId } from "../util/ids.js";
import { remember } from "../data/cache.js";
import { WebhookRequest } from "../types.js";

// The one attacker-reachable entry point: `req` is a public parameter, and the
// identifier lifted off its body reaches the repository through two independent
// service calls — one guarded, one not.
export function handleWebhook(req: WebhookRequest): number {
  const rawId = req.body.id;
  const id = normalizeId(rawId);
  const document = getDocument(id);
  const invoice = getInvoice(id);
  remember(id, document !== undefined);
  return (document ? 1 : 0) + (invoice ? 1 : 0);
}
