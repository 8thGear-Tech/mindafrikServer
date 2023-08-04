import jwt from "jsonwebtoken";
import config from "../config/index.js";

// export function generateToken(user) {
//   const payload = {
//     _id: user._id,
//     email: user.email,
//     username: user.username,
//   };
//   const token = jwt.sign(payload, config.jwt_secret_key, {
//     expiresIn: 60 * 60 * 24,
//   });
//   return token;
// }
export const generateToken = (payload) => {
  try {
    const expiresIn = "1d"; // Token expires in 1 day
    const token = jwt.sign({ payload }, config.jwt_secret_key, {
      expiresIn,
    });
    return token;
  } catch (error) {
    console.error("Error generating token:", error);
    throw error;
  }
};

export function verifyToken(token) {
  return jwt.verify(token, config.jwt_secret_key);
}

//logout util
export function clearTokenCookie(res) {
  res.clearCookie("token");
}

// export const clearTokenCookie = (res) => {
//   res.cookie("token", "", {
//     expires: new Date(0), // Set the cookie to an expired date
//     httpOnly: true, // HttpOnly to prevent access from JavaScript
//     secure: process.env.NODE_ENV === "production", // Set to true in production, false for development
//     sameSite: "strict", // Restrict cookie access to the same site
//   });
// };
// module.exports = { generateToken, verifyToken, clearTokenCookie };
