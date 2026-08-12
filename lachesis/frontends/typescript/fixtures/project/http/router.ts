import { handleWebhook } from "./webhook.js";
import { WebhookRequest } from "../types.js";

type Handler = (req: WebhookRequest) => string;

export class Router {
  routes: Map<string, Handler> = new Map();

  get(path: string, handler: Handler): void {
    this.routes.set(path, handler);
  }

  dispatch(path: string, req: WebhookRequest): string {
    const handler = this.routes.get(path);
    if (handler) {
      return handler(req);
    }
    return "not-found";
  }
}

const router = new Router();
router.get("/documents", handleWebhook);
