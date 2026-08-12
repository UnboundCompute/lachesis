import { Router } from "./router.js";
import {
  archiveRecord, cleanupRecord, deleteRecord, exportRecords, importRecord,
  pruneRecord, purgeRecord, renameRecord, sealRecord, submitRecord, touchRecord,
} from "./handlers.js";

const router = new Router();

router.post("/records.archive", archiveRecord);
router.post("/records.purge", purgeRecord);
router.post("/records.rename", renameRecord);
router.post("/records.delete", deleteRecord);
router.post("/records.touch", touchRecord);
router.post("/records.import", importRecord);
router.post("/records.submit", submitRecord);
router.post("/records.cleanup", cleanupRecord);
router.post("/records.prune", pruneRecord);
router.post("/records.seal", sealRecord);
router.put(
  "/records.export",
  { authRequired: true, permissionsRequired: ["export-records"] },
  exportRecords,
);

export { router };
