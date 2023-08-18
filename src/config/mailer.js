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

//subscribe to newsletter
export const newsletterSubscriptionEmail = async (req, email, firstName) => {
  try {
    const mailOptions = {
      from: process.env.GMAIL_ADDRESS,
      to: email,
      subject: "You have successfully subscribed",
      html: `
    <p>
      Dear ${firstName},
    </p>
    <p>
    A warm thank you for subscribing to MindAfrik's newsletter! Your commitment to emotional well-being is truly appreciated.
    </p>
    <p>
     By joining our newsletter, you're taking an important step toward a more empowered and supported life. We're excited to share valuable insights, tips, and resources with you.
    </p>
    <p>
      Your engagement means a lot to us. 
    </p>
    <p>
    Feel free to reach out at <a href="mailto:support@mindafrik.com">support@mindafrik.com</a> or <a href="tel:+23481331999533">081331999533</a> if you have any questions or need support.
    </p>
    <p>
      Thank you for allowing us to be part of your journey. We look forward to making a positive impact together.
    </p>
    <p>
      Warm regards,
      <br />
      The MindAfrik Team.
    </p>
  `,
    };

    let emailTransporter = await createTransporter();
    await emailTransporter.sendMail(mailOptions);
  } catch (err) {
    console.log("ERROR: ", err);
  }
};
//book a session
export const supportiveListeningSessionEmail = async (
  req,
  email,
  firstName
) => {
  try {
    const mailOptions = {
      from: process.env.GMAIL_ADDRESS,
      to: email,
      subject: "Successful Booking Confirmation",
      html: `
      <p>
      Dear ${firstName},  
    </p>
      <p>
   We appreciate your choice of MindAfrik for your supportive listening. Your well-being matters to us.
    </p>
      <p>
    Your booking has been successfully processed. Expect detailed session scheduling and payment information shortly.
    </p>
      <p>
   Please note that the virtual supportive listening sessions are paid and calculated per hour.
Your first 30 minutes are free. Our <b>N5000</b> per month package includes two hours of weekly counseling.
    </p>
      <p>
   Ensuring your privacy is paramount, ensuring a confidential experience. Our team is dedicated to creating a secure, empathetic space.
    </p>
      <p>
    Reach our support at <a href="mailto:support@mindafrik.com">support@mindafrik.com</a> or <a href="tel:+2348134762115">08134762115</a>
    </p>
      <p>
    We eagerly anticipate supporting you on this journey toward emotional wellness.
    </p>
      <p>
   Best regards,<br/>
   The MindAfrik Team.
    </p>
    `,
    };

    let emailTransporter = await createTransporter();
    await emailTransporter.sendMail(mailOptions);
  } catch (err) {
    console.log("ERROR: ", err);
  }
};
