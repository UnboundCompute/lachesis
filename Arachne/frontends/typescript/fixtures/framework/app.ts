import { createRouter } from "tiny-web";

export function documentHandler(id: string): string {
  return id;
}

const router = createRouter();
router.get("/documents", documentHandler);
