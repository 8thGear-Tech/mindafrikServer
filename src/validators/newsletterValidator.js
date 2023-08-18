import Joi from "joi";

const newsletterValidator = Joi.object({
  firstName: Joi.string(),
  lastName: Joi.string(),
  email: Joi.string(),
  submittedAt: Joi.date().iso(),
});

export { newsletterValidator };
