import { BadUserRequestError, NotFoundError } from "../error/error.js";
import SupportiveListeningSession from "../model/bookSessionModel.js";
import { supportiveListeningSessionValidator } from "../validators/bookSessionValidator.js";
import { supportiveListeningSessionEmail } from "../config/mailer.js";

const supportiveListeningSessionController = {
  newBookingController: async (req, res) => {
    const { error } = supportiveListeningSessionValidator.validate(req.body);
    if (error) throw error;
    const {
      firstName,
      lastName,
      email,
      gender,
      activeMobileNumber,
      alternativeMobileNumber,
      location,
      dateOfBirth,
      age,
      maritalStatus,
      meetingMode,
      counsellingArea,
      counsellingPurpose,
      timeSlot,
      questionCommentSuggestion,
      socialMediaFollowership,
      socialHandleSubscribedTo,
      submittedAt,
    } = req.body;
    const emailExists = await SupportiveListeningSession.find({ email });
    if (emailExists.length > 0)
      throw new BadUserRequestError("User already booked a session");

    const newBooking = await SupportiveListeningSession.create({
      firstName: firstName,
      lastName: lastName,
      email: email,
      gender: gender,
      activeMobileNumber: activeMobileNumber,
      alternativeMobileNumber: alternativeMobileNumber,
      location: location,
      dateOfBirth: dateOfBirth,
      age: age,
      maritalStatus: maritalStatus,
      meetingMode: meetingMode,
      counsellingArea: counsellingArea,
      counsellingPurpose: counsellingPurpose,
      timeSlot: timeSlot,
      questionCommentSuggestion: questionCommentSuggestion,
      socialMediaFollowership: socialMediaFollowership,
      socialHandleSubscribedTo: socialHandleSubscribedTo,
      submittedAt: submittedAt,
    });

    supportiveListeningSessionEmail(
      req,
      newBooking.email,
      newBooking.firstName
    );

    res.status(201).json({
      message: "A new user has booked a Supportive Listening Session",
      status: "Success",
      data: {
        booking: newBooking,
      },
    });
  },
};

export default supportiveListeningSessionController;
