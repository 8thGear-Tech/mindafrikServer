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
import { generateToken } from "../utils/jwtUtils.js";
import { clearTokenCookie } from "../utils/jwtUtils.js";
import { verifyToken } from "../utils/jwtUtils.js";
import saveFileToGridFS from "./saveFileToGridFs.js";

//multer
import multer from "multer";

const storage = multer.memoryStorage(); // Use memory storage for GridFS
export const upload = multer({ storage });

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

    const verificationLink = `https://mindafrikserver.onrender.com/user/verify-email?token=${verificationToken}`;
    // const verificationLink = `http://localhost:4000/user/verify-email?token=${verificationToken}`;
    sendVerificationEmail(req, newUser.email, verificationLink);

    res.status(201).json({
      message: "A new user has been created successfully",
      status: "Success",
      data: {
        user: newUser,
      },
    });
  },
  verifyEmailController: async (req, res) => {
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
    const user = await User.findOne({
      email: req.body?.email,
    });
    if (!user) throw new BadUserRequestError("Incorrect email");
    // const emailExists = await User.findOne({ email });
    if (!user.isEmailVerified) {
      throw new BadUserRequestError(
        "Email not verified. Please verify your email first."
      );
    }
    const hash = bcrypt.compareSync(req.body.password, user.password);
    if (!hash) throw new BadUserRequestError("incorrect password");

    res.status(200).json({
      message: "User login successful",
      status: "Success",
      data: {
        user: user,
        access_token: generateToken(user),
      },
    });
  },
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
    } = req.body;

    const emailExists = await Counsellor.find({ email });
    if (emailExists.length > 0) {
      throw new BadUserRequestError(
        "An account with this email already exists"
      );
    }
    // // Save uploaded file paths to the database
    // const resumePath = req.files.resume[0].path; // Assuming the field name is 'resume'
    // // const resumePath = req.file("resume")[0].path; // Assuming the field name is 'resume'
    // const coverletterPath = req.files.coverletter[0].path; // Assuming the field name is 'coverletter'
    // // const coverletterPath = req.file("coverletter")[0].path; // Assuming the field name is 'coverletter'

    // Inside your controller
    const resumeFile = req.files.resume[0];
    const coverletterFile = req.files.coverletter[0];

    if (!resumeFile || !coverletterFile) {
      throw new BadUserRequestError(
        "Resume and coverletter files are required"
      );
    }

    console.log("Uploaded Files:", req.files);
    const resumeGridFSId = await saveFileToGridFS(resumeFile);
    const coverletterGridFSId = await saveFileToGridFS(coverletterFile);

    // ... (rest of the code)
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);

    // Create new counsellor with file paths
    const newCounsellor = await User.create({
      // ... (other fields)
      firstName: firstName,
      lastName: lastName,
      email: email,
      password: hashedPassword,
      gender: gender,
      phoneNumber: phoneNumber,
      nationality: nationality,
      stateOfOrigin: stateOfOrigin,
      dateOfBirth: dateOfBirth,
      // resume: resumePath, // Store the file path for resume
      // coverletter: coverletterPath, // Store the file path for cover letter
      resume: resumeGridFSId,
      coverletter: coverletterGridFSId,
      school: school,
      degree: degree,
      discipline: discipline,
      experience: experience,
      whyJoinUs: whyJoinUs,
      // ... (rest of the fields)
    });

    // ... (rest of the code)

    // };

    const tokenPayload = { email: newCounsellor.email };
    const verificationToken = generateToken(tokenPayload);
    const verificationLink = `https://mindafrikserver.onrender.com/user/verify-email?token=${verificationToken}`;
    // const verificationLink = `http://localhost:4000/user/verify-email?token=${verificationToken}`;
    sendVerificationEmail(req, newCounsellor.email, verificationLink);

    res.status(201).json({
      message: "A new counsellor account has been created successfully",
      status: "Success",
      data: {
        counsellor: newCounsellor,
      },
    });
    // });
  },

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
