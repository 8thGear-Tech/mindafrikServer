import { BadUserRequestError, NotFoundError } from "../error/error.js";
import NewsletterSubscriber from "../model/newsletterModel.js";
import { newsletterValidator } from "../validators/newsletterValidator.js";
import { newsletterSubscriptionEmail } from "../config/mailer.js";

const newsletterController = {
  newSubscribersController: async (req, res) => {
    const { error } = newsletterValidator.validate(req.body);
    if (error) throw error;
    const { firstName, lastName, email, submittedAt } = req.body;
    const emailExists = await NewsletterSubscriber.find({ email });
    if (emailExists.length > 0)
      throw new BadUserRequestError("User already subscribed");

    const newSubscriber = await NewsletterSubscriber.create({
      firstName: firstName,
      lastName: lastName,
      email: email,
      submittedAt: submittedAt,
    });

    newsletterSubscriptionEmail(
      req,
      newSubscriber.email,
      newSubscriber.firstName
    );

    res.status(201).json({
      message: "A new user has subscribed to newsletter",
      status: "Success",
      data: {
        subscriber: newSubscriber,
      },
    });
  },
};

export default newsletterController;
