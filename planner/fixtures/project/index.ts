import { Router } from "./router.js";
import {
  archiveRecord, deleteRecord, exportRecords, importRecord, purgeRecord,
  renameRecord, submitRecord, touchRecord,
} from "./handlers.js";

const router = new Router();

router.post("/records.archive", archiveRecord);
router.post("/records.purge", purgeRecord);
router.post("/records.rename", renameRecord);
router.post("/records.delete", deleteRecord);
router.post("/records.touch", touchRecord);
router.post("/records.import", importRecord);
router.post("/records.submit", submitRecord);
router.put(
  "/records.export",
  { authRequired: true, permissionsRequired: ["export-records"] },
  exportRecords,
);

export { router };
