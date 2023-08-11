import Joi from "joi";

const newsletterValidator = Joi.object({
  firstName: Joi.string(),
  lastName: Joi.string(),
  email: Joi.string(),
});

export { newsletterValidator };
