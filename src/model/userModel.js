import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
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
  password: {
    type: String,
  },
  userRole: String,
  isEmailVerified: {
    type: Boolean,
    default: false,
  },
  otp: Number,
});

const User = mongoose.model("User", userSchema);

const counsellorSchema = new mongoose.Schema({
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
  password: {
    type: String,
  },
  gender: String,
  phoneNumber: String,
  nationality: String,
  stateOfOrigin: String,
  dateOfBirth: String,
  // resume: {
  //   originalName: String,
  //   mimetype: String,
  //   data: Buffer,
  // },
  resume: String,
  coverletter: String,
  // coverletter: {
  //   originalName: String,
  //   mimetype: String,
  //   data: Buffer,
  // },
  school: String,
  degree: String,
  discipline: String,
  experience: String,
  whyJoinUs: String,
});

const Counsellor = mongoose.model("Counsellor", counsellorSchema);

export { User, Counsellor };
