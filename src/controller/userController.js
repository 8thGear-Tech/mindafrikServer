import express from "express";
import mongoose from "mongoose";
// import MongoStore from "connect-mongo";
import dotenv from "dotenv";
// import session from "express-session";
import { BadUserRequestError, NotFoundError } from "../error/error.js";
import { User, Counsellor } from "../model/userModel.js";
import {
  counsellorSignUpValidator,
  userSignUpValidator,
  verifyEmailValidator,
  otpValidator,
  userLoginValidator,
} from "../validators/userValidator.js";
import jwt from "jsonwebtoken";
import { sendVerificationEmail, sendOtpEmail } from "../config/mailer.js";
import bcrypt from "bcrypt";
import config from "../config/index.js";
import { generateToken, generateRefreshToken } from "../utils/jwtUtils.js";
import { clearTokenCookie } from "../utils/jwtUtils.js";
import { verifyToken, verifyRefreshToken } from "../utils/jwtUtils.js";
import saveFileToGridFS from "./saveFileToGridFs.js";

import cloudinary from "../utils/cloudinary.js";

dotenv.config({ path: "./configenv.env" });

const mongoURI = config.MONGODB_CONNECTION_URL;

// Establish a connection to your MongoDB database
mongoose.connect(mongoURI);

const app = express();

// app.use(
//   session({
//     secret: "your_secret_key_here", // Replace with your own secret key
//     resave: false,
//     saveUninitialized: true,
//     store: MongoStore.create({
//       mongoUrl: mongoURI, // Replace with your MongoDB URL and database name
//       ttl: 14 * 24 * 60 * 60, // = 14 days. Default
//     }),
//     // cookie: { maxAge: 3600000 }, // Set expiration time to 1 hour (in milliseconds)
//   })
// );

//multer
import multer from "multer";
const upload = multer({ dest: "uploads/" });

// import multer from "multer";

// const storage = multer.memoryStorage(); // Use memory storage for GridFS
// export const upload = multer({ storage });

// export const upload = multer();
// export { upload };
// const upload = multer({ dest: "uploads/" });
// const generateToken = (payload) => {
//   try {
//     const expiresIn = "1d"; // Token expires in 1 day
//     const token = jwt.sign({ payload }, process.env.JWT_SECRET, {
//       expiresIn,
//     });
//     return token;
//   } catch (error) {
//     console.error("Error generating token:", error);
//     throw error;
//   }
// };

//multer
// const storage = multer.diskStorage({
//   destination: function (req, file, cb) {
//     cb(null, "/tmp/my-uploads"); // Change this path to where you want to store the uploaded files temporarily
//   },
//   filename: function (req, file, cb) {
//     const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
//     cb(null, file.fieldname + "-" + uniqueSuffix);
//   },
// });

// const fileFilter = (req, file, cb) => {
//   // Only allow certain mimetypes for upload (adjust as needed)
//   const allowedMimeTypes = ["image/jpeg", "image/png", "application/pdf"];

//   if (allowedMimeTypes.includes(file.mimetype)) {
//     cb(null, true); // Accept the file
//   } else {
//     cb(
//       new Error(
//         "Invalid file type. Only JPEG, PNG, and PDF files are allowed."
//       ),
//       false
//     );
//   }
// };

// const upload = multer({ storage: storage, fileFilter: fileFilter });

//old
// const upload = multer({
//   storage: multer.diskStorage({
//     destination: function (req, file, cb) {
//       cb(null, "images"); // Change this path to where you want to store the uploaded files temporarily
//     },
//     filename: function (req, file, cb) {
//       const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
//       console.log("Uploaded File:", file);
//       cb(null, file.fieldname + "-" + uniqueSuffix);
//     },
//   }),
//   fileFilter: function (req, file, cb) {
//     const allowedMimeTypes = ["image/jpeg", "image/png", "application/pdf"];
//     if (allowedMimeTypes.includes(file.mimetype)) {
//       console.log("Accepted File Type:", file.mimetype);
//       cb(null, true); // Accept the file
//     } else {
//       console.log("Invalid File Type:", file.mimetype);
//       cb(
//         new Error(
//           "Invalid file type. Only JPEG, PNG, and PDF files are allowed."
//         ),
//         false
//       );
//     }
//   },
// });

// const uploadResume = upload.single("resume");
// const uploadCoverLetter = upload.single("coverletter");

const userController = {
  // userSignupController: async (req, res) => {
  //   const { error } = userSignUpValidator.validate(req.body);
  //   if (error) throw error;
  //   const { firstName, lastName, email, password } = req.body;
  //   const emailExists = await User.find({ email });
  //   if (emailExists.length > 0)
  //     throw new BadUserRequestError(
  //       "An account with this email already exists"
  //     );

  //   // const saltRounds = config.bcrypt_salt_round;
  //   // const hashedPassword = bcrypt.hashSync(password, saltRounds);

  //   const salt = bcrypt.genSaltSync(10);
  //   const hashedPassword = bcrypt.hashSync(password, salt);

  //   const newUser = await User.create({
  //     firstName: firstName,
  //     lastName: lastName,
  //     email: email,
  //     password: hashedPassword,
  //     userRole: "counsellee",
  //   });

  //   const tokenPayload = { email: newUser.email, userRole: "counsellee" };
  //   // const tokenPayload = { email: user.email, userRole: user.userRole };
  //   const accessToken = generateToken(tokenPayload);
  //   // const verificationToken = generateToken(tokenPayload);

  //   const verificationLink = `https://mindafrikserver.onrender.com/user/verify-email?token=${accessToken}`;
  //   // const verificationLink = `http://localhost:4000/user/verify-email?token=${verificationToken}`;
  //   sendVerificationEmail(req, newUser.email, verificationLink);

  //   res.status(201).json({
  //     message: "A new user has been created successfully",
  //     status: "Success",
  //     data: {
  //       user: newUser,
  //       access_token: accessToken,
  //     },
  //   });
  // },
  userSignupController: async (req, res) => {
    const { error } = userSignUpValidator.validate(req.body);
    if (error) throw error;
    const { firstName, lastName, email, password } = req.body;
    const emailExists = await User.find({ email });
    if (emailExists.length > 0)
      throw new BadUserRequestError(
        "An account with this email already exists"
      );

    // const saltRounds = config.bcrypt_salt_round;
    // const hashedPassword = bcrypt.hashSync(password, saltRounds);

    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);

    const newUser = await User.create({
      firstName: firstName,
      lastName: lastName,
      email: email,
      password: hashedPassword,
    });

    const tokenPayload = { email: newUser.email };
    const verificationToken = generateToken(tokenPayload);

    // const verificationLink = `https://mindafrikserver.onrender.com/user/verify-email?token=${verificationToken}`;
    // const verificationLink = `http://localhost:4000/user/verify-email?token=${verificationToken}`;
    // sendVerificationEmail(req, newUser.email, verificationLink);

    res.status(201).json({
      message: "A new user has been created successfully",
      status: "Success",
      data: {
        user: newUser,
      },
    });
  },
  verifyEEEmailController: async (req, res) => {
    const { token } = req.query;
    try {
      const decoded = verifyToken(token);
      // const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const email = decoded.payload.email;

      const user = await User.findOne({ email });

      if (!user) {
        return res.status(404).json({
          message: "User not found",
          status: "Error",
        });
      }
      if (user.isEmailVerified) {
        return res.status(200).json({
          message: "Email already verified",
          status: "Success",
        });
      }

      user.isEmailVerified = true;
      await user.save();
      res.redirect("https://www.mindafrik.com/email-verified");
      // res.redirect("http://localhost:3000/email-verified");
    } catch (error) {
      console.error("Token validation failed:", error);
      res.status(400).json({
        message: "Invalid token",
        status: "Error",
        // error: error.message,
      });
    }
  },
  sendOtpController: async (req, res) => {
    const { error } = verifyEmailValidator.validate(req.body);
    if (error) throw error;

    const { email } = req.body;

    // Check if user exists
    const emailExists = await User.findOne({ email });
    // if (!emailExists) throw new BadUserRequestError("invalid email");
    // Check if the email is verified
    if (!emailExists.isEmailVerified) {
      throw new BadUserRequestError(
        "Email not verified. Please verify your email first."
      );
    }
    if (emailExists) {
      // Generate OTP
      const otp = Math.floor(Math.random() * 8888 + 1000);

      // Update the OTP for the existing user
      emailExists.otp = otp;
      await emailExists.save();

      // Send OTP email
      sendOtpEmail(email, otp);

      res.status(200).json({
        message: "OTP sent to email for verification",
        data: { user: emailExists },
      });
    } else {
      res.status(404).json({ message: "User not found", status: "Error" });
    }
  },
  verifyOtpController: async (req, res) => {
    const { error } = otpValidator.validate(req.body);
    if (error) throw error;
    const { email } = req.query;
    const user = await User.findOne({ email: email });
    if (!user) throw new BadUserRequestError("invalid email");
    // Check if the email is verified
    if (!user.isEmailVerified) {
      throw new BadUserRequestError(
        "Email not verified. Please verify your email first."
      );
    }

    // if (user.isEmailVerified) {
    //   return res.status(200).json({
    //     message: "Email already verified.",
    //     data: {
    //       user: user,
    //     },
    //   });
    // }
    const { otp } = req.body;
    const verifyOtp = await User.findOne({ email: email, otp: otp });
    if (!verifyOtp) throw new BadUserRequestError("invalid OTP");
    // await User.updateOne({ email: email }, { isEmailVerified: true });
    res.status(200).json({
      message: "OTP verified successfully",
      data: {
        user: verifyOtp,
      },
    });
  },
  userLoginController: async (req, res) => {
    const { error } = userLoginValidator.validate(req.body);
    if (error) throw error;
    const user = await Counsellor.findOne({
      email: req.body?.email,
    });
    if (!user) throw new BadUserRequestError("Incorrect email");
    if (!user.isEmailVerified) {
      throw new BadUserRequestError(
        "Email not verified. Please verify your email first."
      );
    }
    const hash = bcrypt.compareSync(req.body.password, user.password);
    if (!hash) throw new BadUserRequestError("incorrect password");

    const tokenPayload = {
      userId: user._id,
      role: user.role,
      email: user.email,
    };

    const access_token = generateToken(tokenPayload); // Expires in 7 days

    console.log("Access Token:", access_token);

    const refresh_token = generateRefreshToken(tokenPayload);

    console.log("Refresh Token:", refresh_token);
    // Store the refresh token in a secure manner (e.g., in a database)
    user.refresh_token = refresh_token;
    const result = await user.save();
    console.log(result);
    console.log(user.role);

    // Send both tokens to the client
    // res.cookie("refresh_token", refresh_token, {
    res.cookie("jwt", refresh_token, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    }); // Set the refresh token as a secure cookie

    res.status(200).json({
      message: "Counsellor login successful",
      status: "Success",
      data: {
        user: user,
        role: user.role,
        access_token: access_token,
        refresh_token: refresh_token,
      },
    });
  },
  // userLoginController: async (req, res) => {
  //   const { error } = userLoginValidator.validate(req.body);
  //   if (error) throw error;
  //   const user = await Counsellor.findOne({
  //     email: req.body?.email,
  //   });
  //   if (!user) throw new BadUserRequestError("Incorrect email");
  //   // const emailExists = await User.findOne({ email });
  //   if (!user.isEmailVerified) {
  //     throw new BadUserRequestError(
  //       "Email not verified. Please verify your email first."
  //     );
  //   }
  //   const hash = bcrypt.compareSync(req.body.password, user.password);
  //   if (!hash) throw new BadUserRequestError("incorrect password");

  //   // Set session variables
  //   // req.session.userId = user._id;
  //   // req.session.role = user.role;
  //   // Create a session object for the user.
  //   // req.session.user = {
  //   //   userId: user._id,
  //   //   role: user.role,
  //   // };
  //   // Generate the access token and include it in the response

  //   // const tokenPayload = { email: newCounsellor.email, role: "Counsellor" };
  //   // const verificationToken = generateToken(tokenPayload);
  //   const tokenPayload = {
  //     userId: user._id,
  //     role: user.role,
  //     email: user.email,
  //   };
  //   // const access_token = generateToken(tokenPayload);
  //   const access_token = generateToken(tokenPayload); // Expires in 7 days

  //   // Log the access token to check if it contains the correct role
  //   console.log("Access Token:", access_token);

  //   // res.cookie("access_token", access_token, {
  //   //
  //   //   maxAge: 3600000, // Set the cookie to expire after 1 hour (adjust as needed)
  //   //   httpOnly: true, // Prevent JavaScript access to the cookie
  //   //   secure: process.env.NODE_ENV === "production", // Use secure cookies in production
  //   //   // sameSite: "strict", // Prevent CSRF attacks
  //   // });
  //   // const roles = user.roles;

  //   // Set the session cookie.
  //   // res.cookie("session", req.sessionID, sess.cookie);
  //   // const userSession = { email: user.email }; // creating user session to keep user loggedin also on refresh
  //   // req.session.user = userSession; // attach user session to session object from express-session
  //   // req.session.user = user;
  //   // // Create a session object for the user.
  //   // req.session.user = {
  //   //   email,
  //   // };

  //   try {
  //     // Verify the access token
  //     const decodedToken = verifyToken(access_token, config.jwt_secret_key);

  //     console.log("Decoded Token:", decodedToken);

  //     //  const decoded = verifyToken(token);
  //     //  // const decoded = jwt.verify(token, process.env.JWT_SECRET);
  //     //  const email = decoded.payload.email;
  //     //  const role = decoded.role;

  //     if (decodedToken) {
  //       // Extract the user role from the decoded token
  //       const userRole = decodedToken.payload.role;
  //       console.log("Role:", userRole);

  //       res.status(200).json({
  //         message: "Counsellor login successful",
  //         status: "Success",
  //         data: {
  //           user: user,
  //           role: userRole, // Send the role obtained from the token
  //           access_token: access_token,
  //           decodedToken: decodedToken,
  //         },
  //       });
  //     } else {
  //       // Token verification failed
  //       res.status(401).json({
  //         message: "Unauthorized",
  //         status: "Error",
  //         error: "Invalid token",
  //       });
  //     }
  //   } catch (error) {
  //     // An error occurred during token verification
  //     console.error("Error during token verification:", error);
  //     res.status(401).json({
  //       message: "Unauthorized",
  //       status: "Error",
  //       error: "Invalid token",
  //     });
  //   }
  // },
  // RIGHT
  //   res.status(200).json({
  //     message: "Counsellor login successful",
  //     // userSession,
  //     status: "Success",
  //     data: {
  //       user: user,
  //       role: user.role,
  //       // email: user.email,
  //       access_token: access_token,
  //       // access_token: generateToken(user),
  //     },
  //   });
  // },

  handleRefreshToken: async (req, res) => {
    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(401);
    const refresh_token = cookies.jwt;

    const user = await Counsellor.findOne({ refresh_token }).exec();
    if (!user) return res.sendStatus(403); // Forbidden
    // Evaluate jwt

    try {
      const decoded = verifyRefreshToken(
        refresh_token,
        config.refresh_secret_key
      );

      if (user.email === decoded.email) {
        // const role = Object.values(user.role);
        // Check the expiration date of the refresh token
        if (decoded.exp < Date.now() / 1000) {
          return res.sendStatus(401); // Unauthorized
        }

        const role = user.role;
        const access_token = generateToken({
          UserInfo: {
            email: decoded.email,
            role: role,
            // email: decoded.payload.email,
            // role: decoded.payload.role,
          },
        });

        res.json({ role, access_token });
      } else {
        return res.sendStatus(403); // Forbidden
      }
    } catch (error) {
      return res.sendStatus(403); // Forbidden (Token verification failed)
    }
  },
  // const decodedToken = verifyToken(access_token, config.jwt_secret_key);
  //   jwt.verify(refresh_token, config.jwt_secret_key, (err, decoded) => {
  //     if (err || user.email !== decoded.email) return res.sendStatus(403);
  //     const role = Object.values(user.role);
  //     const access_token = jwt.sign(
  //       {
  //         UserInfo: {
  //           email: decoded.email,
  //           role: role,
  //         },
  //       },
  //       config.jwt_secret_key,
  //       { expiresIn: "10s" }
  //     );
  //     res.json({ role, access_token });
  //   });
  // },

  verifyLoginTokenController: async (req, res) => {
    const { access_token } = req.body;
    try {
      const decodedToken = verifyToken(access_token, config.jwt_secret_key);

      if (decodedToken) {
        // Extract the user role from the decoded token
        const userRole = decodedToken.payload.role;
        console.log("Role:", userRole);

        res.status(200).json({
          message: "Token decoded successfully",
          status: "Success",
          data: {
            role: userRole,
          },
        });
      } else {
        // Token verification failed
        res.status(401).json({
          message: "Unauthorized",
          status: "Error",
          error: "Invalid token",
        });
      }
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        res.status(401).json({
          message: "Unauthorized",
          status: "Error",
          error: "Token has expired",
        });
      } else {
        console.error("Error during token verification:", error);
        res.status(401).json({
          message: "Unauthorized",
          status: "Error",
          error: "Invalid token",
        });
      }
    }
  },

  // Verify the access token
  //   try {
  //     const decodedToken = verifyToken(access_token, config.jwt_secret_key);

  //     if (decodedToken) {
  //       res.status(200).json({
  //         message: "Counsellor login successful",
  //         status: "Success",
  //         data: {
  //           user: user,
  //           role: user.role,
  //           access_token: access_token,
  //         },
  //       });
  //     } else {
  //       // Token verification failed
  //       res.status(401).json({
  //         message: "Unauthorized",
  //         status: "Error",
  //         error: "Invalid token",
  //       });
  //     }
  //   } catch (error) {
  //     // An error occurred during token verification
  //     console.error("Error during token verification:", error);
  //     res.status(401).json({
  //       message: "Unauthorized",
  //       status: "Error",
  //       error: "Invalid token",
  //     });
  //   }
  // },
  // Assuming you have a function to verify tokens
  //   const decodedToken = verifyToken(access_token, config.jwt_secret_key);

  //   // If the token verification succeeds, you can proceed
  //   if (decodedToken) {
  //     res.status(200).json({
  //       message: "Counsellor login successful",
  //       status: "Success",
  //       data: {
  //         user: user,
  //         role: user.role,
  //         access_token: access_token,
  //       },
  //     });
  //   } else {
  //     // Token verification failed
  //     res.status(401).json({
  //       message: "Unauthorized",
  //       status: "Error",
  //       error: "Invalid token",
  //     });
  //   }
  // },
  //START
  //   res.status(200).json({
  //     message: "Counsellor login successful",
  //     // userSession,
  //     status: "Success",
  //     data: {
  //       user: user,
  //       role: user.role,
  //       // email: user.email,
  //       access_token: access_token,
  //       // access_token: generateToken(user),
  //     },
  //   });
  // },

  //STOP
  // userLoginController: async (req, res) => {
  //   const { error } = userLoginValidator.validate(req.body);
  //   if (error) throw error;

  //   const accessToken = req.headers.authorization;
  //   if (!accessToken || !accessToken.startsWith("Bearer ")) {
  //     return res.status(401).json({ message: "Invalid access token format" });
  //   }

  //   const token = accessToken.slice(7); // Remove the "Bearer " prefix

  //   try {
  //     const decodedToken = verifyToken(token);
  //     console.log("Decoded Token:", decodedToken); // Use the verifyToken function
  //     const user = await User.findOne({ email: decodedToken.email });
  //     console.log("Found User:", user);
  //     if (!user) {
  //       throw new BadUserRequestError("Incorrect email");
  //     }

  //     // if (!user.isEmailVerified) {
  //     //   throw new BadUserRequestError(
  //     //     "Email not verified. Please verify your email first."
  //     //   );
  //     // }

  //     const hash = bcrypt.compareSync(req.body.password, user.password);
  //     console.log("Password Comparison Result:", hash);
  //     if (!hash) throw new BadUserRequestError("Incorrect password");

  //     res.status(200).json({
  //       message: "User login successful",
  //       status: "Success",
  //       data: {
  //         user: user,
  //       },
  //     });
  //   } catch (error) {
  //     res
  //       .status(401)
  //       .json({ message: "Invalid access token or login credentials" });
  //   }
  // },
  // userLoginController: async (req, res) => {
  //   const { error } = userLoginValidator.validate(req.body);
  //   if (error) throw error;

  //   const accessToken = req.headers.authorization;
  //   if (!accessToken) {
  //     return res.status(401).json({ message: "Access token missing" });
  //   }

  //   try {
  //     const decodedToken = verifyToken(accessToken);
  //     const user = await User.findOne({ email: decodedToken.email });

  //     if (!user) {
  //       throw new BadUserRequestError("Incorrect email");
  //     }

  //     if (!user.isEmailVerified) {
  //       throw new BadUserRequestError(
  //         "Email not verified. Please verify your email first."
  //       );
  //     }

  //     const hash = bcrypt.compareSync(req.body.password, user.password);
  //     if (!hash) throw new BadUserRequestError("Incorrect password");

  //     res.status(200).json({
  //       message: "User login successful",
  //       status: "Success",
  //       data: {
  //         user: user,
  //       },
  //     });
  //   } catch (error) {
  //     res
  //       .status(401)
  //       .json({ message: "Invalid access token or login credentials" });
  //   }
  // },
  // userLoginController: async (req, res) => {
  //   const { error } = userLoginValidator.validate(req.body);
  //   if (error) throw error;
  //   const user = await User.findOne({
  //     email: req.body?.email,
  //   });
  //   if (!user) throw new BadUserRequestError("Incorrect email");
  //   // const emailExists = await User.findOne({ email });
  //   if (!user.isEmailVerified) {
  //     throw new BadUserRequestError(
  //       "Email not verified. Please verify your email first."
  //     );
  //   }
  //   const hash = bcrypt.compareSync(req.body.password, user.password);
  //   if (!hash) throw new BadUserRequestError("incorrect password");

  //   // const accessToken = generateToken({
  //   //   // email: user.email,
  //   //   userRole: user.userRole,
  //   // });
  //   const tokenPayload = { email: user.email, userRole: "counsellee" };
  //   // const tokenPayload = { email: user.email, userRole: user.userRole };
  //   const accessToken = generateToken(tokenPayload);

  //   res.status(200).json({
  //     message: "User login successful",
  //     status: "Success",
  //     data: {
  //       user: user,
  //       // access_token: generateToken(user),
  //       // access_token: generateToken({ userRole: user.userRole }),
  //       // access_token: generateToken({
  //       //   email: user.email,
  //       //   userRole: user.userRole,
  //       // }),
  //       access_token: accessToken,
  //     },
  //   });
  // },
  userLogoutController: async (req, res) => {
    clearTokenCookie(res);
    res.status(200).json({ message: "Logout successful" });
  },

  counsellorController: async (req, res) => {
    const { error } = counsellorSignUpValidator.validate(req.body);
    if (error) throw error;

    // const { resume, coverletter } = req.files.filename;
    // const resume = req.files["resume"][0].filename;
    // const coverletter = req.files["coverletter"][0].filename;

    const resume = cloudinary.v2.uploader.upload(req.file.path);

    // const resume = req.file.filename;
    // const coverletter = req.file.filename;
    const {
      firstName,
      lastName,
      email,
      password,
      gender,
      phoneNumber,
      nationality,
      stateOfOrigin,
      dateOfBirth,
      school,
      degree,
      discipline,
      experience,
      whyJoinUs,
      // submittedAt,
    } = req.body;

    const emailExists = await Counsellor.find({ email });
    if (emailExists.length > 0) {
      throw new BadUserRequestError(
        "An account with this email already exists"
      );
    }

    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);

    const newCounsellor = await Counsellor.create({
      firstName: firstName,
      lastName: lastName,
      email: email,
      password: hashedPassword,
      gender: gender,
      phoneNumber: phoneNumber,
      nationality: nationality,
      stateOfOrigin: stateOfOrigin,
      dateOfBirth: dateOfBirth,
      resume: resume.secure_url,
      resume_id: resume.public_id,
      // resume: resume,
      // coverletter: coverletter,
      school: school,
      degree: degree,
      discipline: discipline,
      experience: experience,
      whyJoinUs: whyJoinUs,
      role: "Counsellor",
      // submittedAt: submittedAt,
    });
    newCounsellor.save();

    // const tokenPayload = { email: newCounsellor.email };
    const tokenPayload = { email: newCounsellor.email, role: "Counsellor" };
    const verificationToken = generateToken(tokenPayload);
    const verificationLink = `https://mindafrikserver.onrender.com/user/verify-email?token=${verificationToken}`;
    // const verificationLink = `http://localhost:4000/user/verify-email?token=${verificationToken}`;
    sendVerificationEmail(
      req,
      newCounsellor.email,
      newCounsellor.firstName,
      verificationLink
    );

    console.log(req.body);
    res.status(201).json({
      message: "A new counsellor account has been created successfully",
      status: "Success",
      data: {
        counsellor: newCounsellor,
      },
    });
    // });
  },
  verifyEmailController: async (req, res) => {
    const { token } = req.query;
    try {
      const decoded = verifyToken(token);
      // const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const email = decoded.payload.email;
      const role = decoded.role;

      const user = await Counsellor.findOne({ email });

      if (!user) {
        return res.status(404).json({
          message: "User not found",
          status: "Error",
        });
      }
      if (user.isEmailVerified) {
        return res.status(200).json({
          message: "Email already verified",
          status: "Success",
        });
      }

      user.isEmailVerified = true;
      await user.save();
      res.redirect("https://www.mindafrik.com/email-verified");
      // res.redirect("http://localhost:3000/email-verified");
    } catch (error) {
      console.error("Token validation failed:", error);
      res.status(400).json({
        message: "Invalid token",
        status: "Error",
        // error: error.message,
      });
    }
  },

  //latest
  // counsellorController: async (req, res) => {
  //   const { error } = counsellorSignUpValidator.validate(req.body);
  //   if (error) throw error;

  //   const {
  //     firstName,
  //     lastName,
  //     email,
  //     password,
  //     gender,
  //     phoneNumber,
  //     nationality,
  //     stateOfOrigin,
  //     dateOfBirth,
  //     school,
  //     degree,
  //     discipline,
  //     experience,
  //     whyJoinUs,
  //   } = req.body;

  //   const emailExists = await Counsellor.find({ email });
  //   if (emailExists.length > 0) {
  //     throw new BadUserRequestError(
  //       "An account with this email already exists"
  //     );
  //   }
  //   // // Save uploaded file paths to the database
  //   // const resumePath = req.files.resume[0].path; // Assuming the field name is 'resume'
  //   // // const resumePath = req.file("resume")[0].path; // Assuming the field name is 'resume'
  //   // const coverletterPath = req.files.coverletter[0].path; // Assuming the field name is 'coverletter'
  //   // // const coverletterPath = req.file("coverletter")[0].path; // Assuming the field name is 'coverletter'

  //   // Inside your controller
  //   // const resumeFile = req.files.resume[0];
  //   // const coverletterFile = req.files.coverletter[0];
  //   const resumeFile = req.files?.resume?.[0];
  //   const coverletterFile = req.files?.coverletter?.[0];

  //   if (!resumeFile || !coverletterFile) {
  //     throw new BadUserRequestError(
  //       "Resume and coverletter files are required"
  //     );
  //   }

  //   console.log("Uploaded Files:", req.files);
  //   const resumeGridFSId = await saveFileToGridFS(resumeFile);
  //   const coverletterGridFSId = await saveFileToGridFS(coverletterFile);

  //   // ... (rest of the code)
  //   const salt = bcrypt.genSaltSync(10);
  //   const hashedPassword = bcrypt.hashSync(password, salt);

  //   // Create new counsellor with file paths
  //   const newCounsellor = await User.create({
  //     // ... (other fields)
  //     firstName: firstName,
  //     lastName: lastName,
  //     email: email,
  //     password: hashedPassword,
  //     gender: gender,
  //     phoneNumber: phoneNumber,
  //     nationality: nationality,
  //     stateOfOrigin: stateOfOrigin,
  //     dateOfBirth: dateOfBirth,
  //     // resume: resumePath, // Store the file path for resume
  //     // coverletter: coverletterPath, // Store the file path for cover letter
  //     resume: resumeGridFSId,
  //     coverletter: coverletterGridFSId,
  //     school: school,
  //     degree: degree,
  //     discipline: discipline,
  //     experience: experience,
  //     whyJoinUs: whyJoinUs,
  //     // ... (rest of the fields)
  //   });

  //   // ... (rest of the code)

  //   // };

  //   const tokenPayload = { email: newCounsellor.email };
  //   const verificationToken = generateToken(tokenPayload);
  //   const verificationLink = `https://mindafrikserver.onrender.com/user/verify-email?token=${verificationToken}`;
  //   // const verificationLink = `http://localhost:4000/user/verify-email?token=${verificationToken}`;
  //   sendVerificationEmail(req, newCounsellor.email, verificationLink);

  //   res.status(201).json({
  //     message: "A new counsellor account has been created successfully",
  //     status: "Success",
  //     data: {
  //       counsellor: newCounsellor,
  //     },
  //   });
  //   // });
  // },

  //   counsellorController: async (req, res) => {
  //     try {
  //       const { error } = counsellorSignUpValidator.validate(req.body);
  //       if (error) throw error;

  //       const {
  //         firstName,
  //         lastName,
  //         email,
  //         password,
  //         gender,
  //         phoneNumber,
  //         nationality,
  //         stateOfOrigin,
  //         dateOfBirth,
  //         school,
  //         degree,
  //         discipline,
  //         experience,
  //         whyJoinUs,
  //       } = req.body;

  //       const emailExists = await Counsellor.find({ email });
  //       if (emailExists.length > 0) {
  //         throw new BadUserRequestError(
  //           "An account with this email already exists"
  //         );
  //       }

  //       // Handle file uploads using Multer middleware
  //       // upload.single(resume)(req, res, async (err) => {
  //       //   if (err) {
  //       //     return res.status(400).json({ error: err.message });
  //       //   }
  //       //   console.log("Resume File:", req.file);
  //       //   // Resume file uploaded successfully
  //       //   const resume = req.file;

  //       //   // Handle cover letter file upload
  //       //   upload.single(coverletter)(req, res, async (err) => {
  //       //     if (err) {
  //       //       return res.status(400).json({ error: err.message });
  //       //     }

  //       //     // Cover letter file uploaded successfully
  //       //     const coverletter = req.file;
  //       // upload.fields([{ name: "resume" }, { name: "coverletter" }])(
  //       //   req,
  //       //   res,
  //       //   async (err) => {
  //       //     if (err) {
  //       //       return res.status(400).json({ error: err.message });
  //       //     }

  //       //     // Resume and coverletter files uploaded successfully
  //       //     const resume = req.files["resume"][0];
  //       //     const coverletter = req.files["coverletter"][0];
  //       upload.single("resume", (req, file, cb) => {
  //   if (req.file) {
  //     // Resume file uploaded successfully
  //     const resume = req.file;
  //     cb(null, resume);
  //   } else {
  //     // No resume file uploaded
  //     throw new Error("Please upload a resume file");
  //   }
  //       });

  //       upload.single("coverletter", (req, file, cb) => {
  //   if (req.file) {
  //     // Resume file uploaded successfully
  //     const coverletter = req.file;
  //     cb(null, coverletter);
  //   } else {
  //     // No resume file uploaded
  //     throw new Error("Please upload a resume file");
  //   }
  // });

  //           const salt = bcrypt.genSaltSync(10);
  //           const hashedPassword = bcrypt.hashSync(password, salt);

  //           // Save data to the database
  //           const newCounsellor = await Counsellor.create({
  //             firstName: firstName,
  //             lastName: lastName,
  //             email: email,
  //             password: hashedPassword,
  //             gender: gender,
  //             phoneNumber: phoneNumber,
  //             nationality: nationality,
  //             stateOfOrigin: stateOfOrigin,
  //             dateOfBirth: dateOfBirth,
  //             resume: {
  //               originalName: resume.originalname,
  //               mimetype: resume.mimetype,
  //               data: resume.buffer,
  //             },
  //             coverletter: {
  //               originalName: coverletter.originalname,
  //               mimetype: coverletter.mimetype,
  //               data: coverletter.buffer,
  //             },
  //             school: school,
  //             degree: degree,
  //             discipline: discipline,
  //             experience: experience,
  //             whyJoinUs: whyJoinUs,
  //           });

  //           const tokenPayload = { email: newCounsellor.email };
  //           const verificationToken = generateToken(tokenPayload);
  //           const verificationLink = `http://localhost:4000/user/verify-email?token=${verificationToken}`;
  //           sendVerificationEmail(req, newCounsellor.email, verificationLink);

  //           res.status(201).json({
  //             message: "A new counsellor account has been created successfully",
  //             status: "Success",
  //             data: {
  //               counsellor: newCounsellor,
  //             },
  //           });
  //           // });
  //         }
  //       );
  //     } catch (error) {
  //       res.status(500).json({
  //         message: "An error occurred while processing the request",
  //         status: "Error",
  //         error: error.message,
  //       });
  //     }
  //   },

  //old
  // counsellorController: async (req, res) => {
  //   const { resume, coverletter } = await upload.single(
  //     "resume",
  //     (req, file, cb) => {
  //       if (req.file) {
  //         // Resume file uploaded successfully
  //         const resume = req.file;
  //         cb(null, resume);
  //       } else {
  //         // No resume file uploaded
  //         throw new Error("Please upload a resume file");
  //       }
  //     }
  //   );
  // try {
  // Upload user's resume and cover letter files
  // upload.single("resume", (req, file, cb) => {
  //   if (req.file) {
  //     // Resume file uploaded successfully
  //     const resume = req.file;
  //     cb(null, resume);
  //   } else {
  //     // No resume file uploaded
  //     throw new Error("Please upload a resume file");
  //   }
  // });

  // upload.single("coverletter", (req, file, cb) => {
  //   if (req.file) {
  //     // Resume file uploaded successfully
  //     const coverletter = req.file;
  //     cb(null, coverletter);
  //   } else {
  //     // No resume file uploaded
  //     throw new Error("Please upload a cover letter file");
  //   }
  // });

  // Save data to the database

  //old
  // const newCounsellor = await Counsellor.create({
  //   firstName: firstName,
  //   lastName: lastName,
  //   email: email,
  //   password: hashedPassword,
  //   gender: gender,
  //   phoneNumber: phoneNumber,
  //   nationality: nationality,
  //   stateOfOrigin: stateOfOrigin,
  //   dateOfBirth: dateOfBirth,
  //   resume: {
  //     originalName: resume.originalname,
  //     mimetype: resume.mimetype,
  //     data: resume.buffer,
  //   },
  //   coverletter: {
  //     originalName: coverletter.originalname,
  //     mimetype: coverletter.mimetype,
  //     data: coverletter.buffer,
  //   },
  //   school: school,
  //   degree: degree,
  //   discipline: discipline,
  //   experience: experience,
  //   whyJoinUs: whyJoinUs,
  // });

  // const tokenPayload = { email: newCounsellor.email };
  // const verificationToken = generateToken(tokenPayload);
  // const verificationLink = `http://localhost:4000/user/verify-email?token=${verificationToken}`;
  // sendVerificationEmail(req, newCounsellor.email, verificationLink);

  // res.status(201).json({
  //   message: "A new counsellor account has been created successfully",
  //   status: "Success",
  //   data: {
  //     counsellor: newCounsellor,
  //   },
  // });
  // } catch (error) {
  //   // Handle errors that are thrown during the file upload process
  //   res.status(400).json({
  //     error: error.message,
  //   });
  // }
  // },
  // counsellorController: async (req, res) => {
  //   const { error } = counsellorSignUpValidator.validate(req.body);
  //   if (error) throw error;
  //   const {
  //     firstName,
  //     lastName,
  //     email,
  //     password,
  //     gender,
  //     phoneNumber,
  //     nationality,
  //     stateOfOrigin,
  //     // resume,
  //     resume = req.file("resume"),
  //     dateOfBirth,
  //     school,
  //     // coverletter,
  //     coverletter = req.file("coverletter"),
  //     discipline,
  //     experience,
  //     degree,
  //     whyJoinUs,
  //   } = req.body;

  //   const emailExists = await Counsellor.find({ email });
  //   if (emailExists.length > 0)
  //     throw new BadUserRequestError(
  //       "An account with this email already exists"
  //     );

  //   // const saltRounds = config.bcrypt_salt_round;
  //   // const hashedPassword = bcrypt.hashSync(password, saltRounds);

  //   const salt = bcrypt.genSaltSync(10);
  //   const hashedPassword = bcrypt.hashSync(password, salt);

  //   const newCounsellor = await User.create({
  //     firstName: firstName,
  //     lastName: lastName,
  //     email: email,
  //     password: hashedPassword,
  //     gender: gender,
  //     phoneNumber: phoneNumber,
  //     nationality: nationality,
  //     stateOfOrigin: stateOfOrigin,
  //     resume: resume,
  //     dateOfBirth: dateOfBirth,
  //     school: school,
  //     coverletter: coverletter,
  //     discipline: discipline,
  //     experience: experience,
  //     degree: degree,
  //     whyJoinUs: whyJoinUs,
  //   });

  //   const tokenPayload = { email: newCounsellor.email };
  //   const verificationToken = generateToken(tokenPayload);

  //   const verificationLink = `https://mindafrikserver.onrender.com/user/verify-email?token=${verificationToken}`;
  //   // const verificationLink = `http://localhost:4000/user/verify-email?token=${verificationToken}`;
  //   sendVerificationEmail(req, newUser.email, verificationLink);

  //   res.status(201).json({
  //     message: "A new counsellor account has been created successfully",
  //     status: "Success",
  //     data: {
  //       counsellor: newCounsellor,
  //     },
  //   });
  // },
};
export default userController;
