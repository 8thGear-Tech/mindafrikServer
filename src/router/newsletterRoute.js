import express from "express";
import newsletterController from "../controller/newsletterController.js";
import tryCatchHandler from "../utils/tryCatchHandler.js";

const newsletterRouter = express.Router();

newsletterRouter.post(
  "/new-subscriber",
  tryCatchHandler(newsletterController.newSubscribersController)
);

export default newsletterRouter;
