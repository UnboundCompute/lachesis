import { Router } from "./router.js";
import { archiveRecord, exportRecords, purgeRecord } from "./handlers.js";

const router = new Router();

router.post("/records.archive", archiveRecord);
router.post("/records.purge", purgeRecord);
router.put(
  "/records.export",
  { authRequired: true, permissionsRequired: ["export-records"] },
  exportRecords,
);

export { router };
