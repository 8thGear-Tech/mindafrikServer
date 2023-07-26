import express from "express";
import userController from "../controller/userController.js";
import tryCatchHandler from "../utils/tryCatchHandler.js";

const userRouter = express.Router();

userRouter.post(
  "/signup",
  tryCatchHandler(userController.userSignupController)
);

export default userRouter;
