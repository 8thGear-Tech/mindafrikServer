import express from "express";
import userController from "../controller/userController.js";
import tryCatchHandler from "../utils/tryCatchHandler.js";
import roleAuthMiddleware from "../middleware/userAuthMiddleware.js";
// import { upload } from "../controller/userController.js";
import multer from "multer";

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    // const uniqueSuffix = Date.now();
    // cb(null, uniqueSuffix + file.originalname);
    //new
    cb(
      null,
      `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`
    );
  },
});

const upload = multer({ storage: storage });

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

// Modify the login route to include the middleware with the allowed roles
// userRouter.post(
//   "/login",
//   roleAuthMiddleware(["counsellee", "admin", "counsellor"]),
//   tryCatchHandler(userController.userLoginController)
// );

userRouter.post("/login", tryCatchHandler(userController.userLoginController));
userRouter.post(
  "/logout",
  tryCatchHandler(userController.userLogoutController)
);

//counsellor
userRouter.post(
  "/sign-up-as-a-counsellor",
  upload.single("resume"),
  tryCatchHandler(userController.counsellorController)
);
// userRouter.post(
//   "/sign-up-as-a-counsellor",
//   upload.fields([
//     { name: "resume", maxCount: 1 },
//     { name: "coverletter", maxCount: 1 },
//   ]),
//   tryCatchHandler(userController.counsellorController)
// );

export default userRouter;
