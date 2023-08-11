import mongoose from "mongoose";

const supportiveListeningSessionSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: {
    type: String,
    validators: {
      match: [
        /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/,
        "Please add a valid email string to the email path.",
      ],
    },
  },
  gender: String,
  activeMobileNumber: String,
  alternativeMobileNumber: String,
  location: String,
  dateOfBirth: String,
  age: String,
  maritalStatus: String,
  meetingMode: String,
  counsellingArea: String,
  counsellingPurpose: String,
  timeSlot: String,
  questionCommentSuggestion: String,
  socialMediaFollowership: String,
  socialHandleSubscribedTo: String,
});

const SupportiveListeningSession = mongoose.model(
  "SupportiveListeningSession",
  supportiveListeningSessionSchema
);

export default SupportiveListeningSession;
