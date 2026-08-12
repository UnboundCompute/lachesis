import { Router } from "./router.js";
import {
  archiveRecord, deleteRecord, exportRecords, purgeRecord, renameRecord,
  touchRecord,
} from "./handlers.js";

const router = new Router();

router.post("/records.archive", archiveRecord);
router.post("/records.purge", purgeRecord);
router.post("/records.rename", renameRecord);
router.post("/records.delete", deleteRecord);
router.post("/records.touch", touchRecord);
router.put(
  "/records.export",
  { authRequired: true, permissionsRequired: ["export-records"] },
  exportRecords,
);

export { router };
