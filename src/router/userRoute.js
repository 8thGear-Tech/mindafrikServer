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
userRouter.patch(
  "/send-otp",
  tryCatchHandler(userController.sendOtpController)
);
userRouter.patch(
  "/verify-otp",
  tryCatchHandler(userController.verifyOtpController)
);
// userRouter.patch(
//   "/reset-password",
//   tryCatchHandler(userController.resetPasswordController)
// );
userRouter.post("/login", tryCatchHandler(userController.userLoginController));
userRouter.post(
  "/logout",
  tryCatchHandler(userController.userLogoutController)
);

export default userRouter;
