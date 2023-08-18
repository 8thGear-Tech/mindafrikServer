import Joi from "joi";

const userSignUpValidator = Joi.object({
  firstName: Joi.string(),
  lastName: Joi.string(),
  email: Joi.string(),
  password: Joi.string()
    .min(8)
    .required()
    .pattern(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/
    )
    .message(
      "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character"
    ),
  // userRole: Joi.string(),
});
const counsellorSignUpValidator = Joi.object({
  // firstName: Joi.string(),
  // lastName: Joi.string(),
  // email: Joi.string().email(),
  // password: Joi.string()
  //   .min(8)
  //   .required()
  //   .pattern(
  //     /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/
  //   )
  //   .message(
  //     "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character"
  //   ),
  // gender: Joi.string(),
  // phoneNumber: Joi.string(),
  // nationality: Joi.string(),
  // stateOfOrigin: Joi.string(),
  // dateOfBirth: Joi.string(),
  resume: Joi.string(),
  // coverletter: Joi.any(),
  // school: Joi.string(),
  // degree: Joi.string(),
  // discipline: Joi.string(),
  // experience: Joi.string(),
  // whyJoinUs: Joi.string(),
});
const verifyEmailValidator = Joi.object({
  email: Joi.string().required().email().message({
    "string.pattern.base": "Invalid email format",
  }),
});
const otpValidator = Joi.object({
  otp: Joi.number().required(),
});

const userLoginValidator = Joi.object({
  email: Joi.string().required().email(),
  password: Joi.string().required(),
});

export {
  counsellorSignUpValidator,
  userSignUpValidator,
  verifyEmailValidator,
  otpValidator,
  userLoginValidator,
};

// export default userSignUpValidator;
