import Joi from "joi";

const supportiveListeningSessionValidator = Joi.object({
  firstName: Joi.string(),
  lastName: Joi.string(),
  email: Joi.string(),
  gender: Joi.string(),
  activeMobileNumber: Joi.string(),
  alternativeMobileNumber: Joi.string(),
  location: Joi.string(),
  dateOfBirth: Joi.string(),
  age: Joi.string(),
  maritalStatus: Joi.string(),
  meetingMode: Joi.string(),
  counsellingArea: Joi.string(),
  counsellingPurpose: Joi.string(),
  timeSlot: Joi.string(),
  questionCommentSuggestion: Joi.string(),
  socialMediaFollowership: Joi.string(),
  socialHandleSubscribedTo: Joi.array() // Change to Joi.array() to match the array type
    .items(Joi.string()) // You can add validation for each string item if needed
    .min(1) // Ensure at least one item is selected
    .required(),
  submittedAt: Joi.date().iso(),
});

export { supportiveListeningSessionValidator };
