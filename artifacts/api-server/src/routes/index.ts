import { Router, type IRouter } from "express";
import healthRouter from "./health";
import scansRouter from "./scans";
import reportsRouter from "./reports";
import chatRouter from "./chat";
import dashboardRouter from "./dashboard";
import repairRouter from "./repair";

const router: IRouter = Router();

router.use(healthRouter);
router.use(dashboardRouter);
router.use(scansRouter);
router.use(reportsRouter);
router.use(chatRouter);
router.use(repairRouter);

export default router;
