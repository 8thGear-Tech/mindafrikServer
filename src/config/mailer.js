import nodemailer from "nodemailer";
import dotenv from "dotenv";
import { google } from "googleapis";

const OAuth2 = google.auth.OAuth2;
dotenv.config({ path: "./configenv.env" });

const createTransporter = async () => {
  try {
    const oauth2Client = new OAuth2(
      process.env.CLIENT_ID,
      process.env.CLIENT_SECRET,
      process.env.REDIRECT_URL
    );

    oauth2Client.setCredentials({
      refresh_token: process.env.REFRESH_TOKEN,
    });

    const accessToken = await new Promise((resolve, reject) => {
      oauth2Client.getAccessToken((err, token) => {
        if (err) {
          console.log("*ERR: ", err);
          reject();
        }
        resolve(token);
      });
    });

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        type: "OAuth2",
        user: process.env.GMAIL_ADDRESS,
        clientId: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        refreshToken: process.env.REFRESH_TOKEN,
        accessToken,
      },
    });
    return transporter;
  } catch (err) {
    console.log("ERROR: ", err);
    throw err;
  }
};

export const sendVerificationEmail = async (req, email, verificationLink) => {
  try {
    const mailOptions = {
      from: process.env.GMAIL_ADDRESS,
      to: email,
      subject: "Email Verification",
      html: `<p>Please verify your email by clicking <a href="${verificationLink}">here</a>.</p>`,
    };

    let emailTransporter = await createTransporter();
    await emailTransporter.sendMail(mailOptions);
  } catch (err) {
    console.log("ERROR: ", err);
  }
};
export const sendOtpEmail = async (email, otp) => {
  try {
    const mailOptions = {
      from: process.env.GMAIL_ADDRESS,
      to: email,
      subject: "Password Reset",
      html: `
          <p>You have requested to reset your password. Your OTP for password reset is: ${otp}.</p>
          <p>If you didn't request this, please ignore this email.</p>
        `,
    };

    let emailTransporter = await createTransporter();
    await emailTransporter.sendMail(mailOptions);
  } catch (err) {
    console.log("ERROR: ", err);
  }
};
