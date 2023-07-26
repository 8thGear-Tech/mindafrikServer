import { BadUserRequestError, NotFoundError } from "../error/error.js";
import User from "../model/userModel.js";
import {
  userSignUpValidator,
  userLoginValidator,
} from "../validators/userValidator.js";
import jwt from "jsonwebtoken";
import { sendVerificationEmail } from "../config/mailer.js";
import bcrypt from "bcrypt";
import config from "../config/index.js";

const generateToken = (payload) => {
  try {
    const expiresIn = "1d"; // Token expires in 1 day
    const token = jwt.sign({ payload }, process.env.JWT_SECRET, {
      expiresIn,
    });
    return token;
  } catch (error) {
    console.error("Error generating token:", error);
    throw error;
  }
};

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

    // const verificationLink = `https://mindafrikserver.onrender.com/user/verify-email?token=${verificationToken}`;
    const verificationLink = `http://localhost:4000/user/verify-email?token=${verificationToken}`;
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
      // res.redirect("https://www.mindafrik.com/email-verified");
      res.redirect("http://localhost:3000/email-verified");
    } catch (error) {
      console.error("Token validation failed:", error);
      res.status(400).json({
        message: "Invalid token",
        status: "Error",
      });
    }
  },
  userLoginController: async (req, res) => {
    const { error } = userLoginValidator.validate(req.body);
    if (error) throw error;
    const user = await User.findOne({
      email: req.body?.email,
    });
    if (!user) throw new BadUserRequestError("Incorrect email");
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
};
export default userController;
