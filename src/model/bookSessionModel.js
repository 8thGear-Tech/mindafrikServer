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
  socialHandleSubscribedTo: [String],
  submittedAt: { type: Date, default: Date.now },
  // submittedAt: String,
});

// supportiveListeningSessionSchema.pre("save", function (next) {
//   const currentDate = new Date();
//   this.submittedAt = currentDate.toISOString().slice(0, 16);
//   next();
// });

const SupportiveListeningSession = mongoose.model(
  "SupportiveListeningSession",
  supportiveListeningSessionSchema
);

export default SupportiveListeningSession;
