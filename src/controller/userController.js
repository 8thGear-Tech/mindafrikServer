import { BadUserRequestError, NotFoundError } from "../error/error.js";
import User from "../model/userModel.js";
import {
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

const userController = {
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
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
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
    // const { email, password } = req.body;
    const user = await User.findOne({
      email: req.body?.email,
    });
    if (!user) throw new BadUserRequestError("Email does not exist");
    // if (!user) throw new BadUserRequestError("Incorrect email");
    // const emailExists = await User.findOne({ email });
    if (!user.isEmailVerified) {
      throw new BadUserRequestError(
        "Email not verified. Please verify your email first."
      );
    }
    const hash = bcrypt.compareSync(req.body.password, user.password);
    if (!hash) throw new BadUserRequestError("incorrect password");

    // Generate the authentication token
    const tokenPayload = { email: user.email };
    const authToken = generateToken(tokenPayload);

    // Set the authToken as an HTTP-only cookie
    res.cookie("authToken", authToken, {
      httpOnly: true,
      secure: true, // Make sure to use secure: true in production (HTTPS)
      // You can also set other options like 'maxAge' to control the cookie expiration
    });

    res.status(200).json({
      message: "User login successful",
      status: "Success",
      data: {
        user: user,
        access_token: generateToken(user),
      },
    });
    //    } catch (error) {
    //   console.error("Error during login:", error);
    //   res.status(400).json({
    //     message: "Login failed",
    //     status: "Error",
    //   });
    // }
  },
  userLogoutController: async (req, res) => {
    clearTokenCookie(res);
    res.status(200).json({ message: "Logout successful" });
  },
};
export default userController;
