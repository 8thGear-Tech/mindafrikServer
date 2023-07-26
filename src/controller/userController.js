import { BadUserRequestError, NotFoundError } from "../error/error.js";
import User from "../model/userModel.js";
import userSignUpValidator from "../validators/userValidator.js";

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

    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password,
    });

    res.status(201).json({
      message: "A new user has been created successfully",
      status: "Success",
      data: {
        user: newUser,
      },
    });
  },
};

export default userController;
