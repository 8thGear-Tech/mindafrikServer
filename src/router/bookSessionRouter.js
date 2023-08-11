import express from "express";
import supportiveListeningSessionController from "../controller/bookSession.js";
import tryCatchHandler from "../utils/tryCatchHandler.js";

const supportiveListeningSessionRouter = express.Router();

supportiveListeningSessionRouter.post(
  "/book-a-supportive-listening-session",
  tryCatchHandler(supportiveListeningSessionController.newBookingController)
);

export default supportiveListeningSessionRouter;
