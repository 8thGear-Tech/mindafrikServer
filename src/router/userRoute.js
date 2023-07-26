import express from "express";
import userController from "../controller/userController.js";
import tryCatchHandler from "../utils/tryCatchHandler.js";

const userRouter = express.Router();

userRouter.post(
  "/signup",
  tryCatchHandler(userController.userSignupController)
);
userRouter.get(
  "/verify-email",
  tryCatchHandler(userController.verifyEmailController)
);
userRouter.post("/login", tryCatchHandler(userController.userLoginController));

export default userRouter;
