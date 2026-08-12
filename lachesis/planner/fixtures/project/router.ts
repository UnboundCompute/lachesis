// A minimal registration surface, in the two shapes the planner has to tell apart:
// `post(path, handler)`, where any requirement must live in code, and
// `put(path, options, handler)`, where the requirement is declared on the
// registration itself and is never called.

export interface Request {
  userId: string;
  recordId: string;
}

export interface RouteOptions {
  authRequired: boolean;
  permissionsRequired: string[];
}

type Handler = (req: Request) => string;

export class Router {
  routes: Map<string, Handler> = new Map();

  post(path: string, handler: Handler): void {
    this.routes.set(path, handler);
  }

  put(path: string, options: RouteOptions, handler: Handler): void {
    void options;
    this.routes.set(path, handler);
  }

  dispatch(path: string, req: Request): string {
    const handler = this.routes.get(path);
    if (handler) {
      return handler(req);
    }
    return "not-found";
  }
}
