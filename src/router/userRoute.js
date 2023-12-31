import express from "express";
import userController from "../controller/userController.js";
import tryCatchHandler from "../utils/tryCatchHandler.js";
import { checkUserRole } from "../utils/jwtUtils.js";
// import checkUserRole from "../middleware/userAuthMiddleware.js";
import roleAuthMiddleware from "../middleware/userAuthMiddleware.js";
// import { upload } from "../controller/userController.js";
import multer from "multer";
// import { verifyToken } from "../utils/jwtUtils.js";

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    // const uniqueSuffix = Date.now();
    cb(null, file.originalname);
    // cb(null, uniqueSuffix + file.originalname);
    // new
    // cb(
    //   null,
    //   `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`
    // );
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
userRouter.get(
  "/refresh-token",
  tryCatchHandler(userController.handleRefreshToken)
);
// userRouter.get(
//   "/decode-token",
//   tryCatchHandler(userController.verifyLoginTokenController)
// );
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

//counsellee
userRouter.post(
  "/sign-up-as-a-counsellee",
  tryCatchHandler(userController.counselleeController)
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
