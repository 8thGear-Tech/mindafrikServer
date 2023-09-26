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
  role: {
    type: String,
    enum: ["Admin", "Counsellor", "Counsellee"],
    default: "Counsellee", // Assuming default role for a counsellee
  },
  refresh_token: String,
  // applicationDate: {
  //   type: Date,
  //   default: Date.now,
  //   get: (date) => moment(date).format("DD/MM/YY"),
  // },
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
  resume_id: String,
  // coverletter: String,
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
  isEmailVerified: {
    type: Boolean,
    default: false,
  },
  otp: Number,
  // roles: {
  //   type: String,
  //   enum: ["Counsellor"],
  //   default: "Counsellor",
  // },
  role: {
    type: String,
    enum: ["Admin", "Counsellor", "Counsellee"],
    default: "Counsellor", // Assuming default role for a counsellor
  },
  refresh_token: String,
  // applicationDate: {
  //   type: Date,
  //   default: Date.now,
  //   get: (date) => moment(date).format("DD/MM/YY"),
  // },
  //new
  // submittedAt: String,
});

const AllUsers = mongoose.model(
  "AllUsers",
  new mongoose.Schema({
    counsellor: counsellorSchema,
    counsellee: userSchema,
  })
);
//new
// counsellorSchema.pre("save", function (next) {
//   const currentDate = new Date();
//   this.submittedAt = currentDate.toISOString().slice(0, 16);
//   next();
// });

const Counsellor = mongoose.model("Counsellor", counsellorSchema);

export { User, Counsellor, AllUsers };
