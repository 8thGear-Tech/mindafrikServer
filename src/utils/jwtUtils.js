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
  // return jwt.verify(token, config.jwt_secret_key);
  try {
    return jwt.verify(token, config.jwt_secret_key);
  } catch (error) {
    // Token is either expired or invalid
    throw new Error("Expired token");
  }
}

// Middleware for checking user roles
export const checkUserRole = (allowedRoles) => {
  return (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
      return res.status(403).json({ message: "Access token not provided" });
    }
    try {
      const decoded = verifyToken(token);
      const userRoles = decoded.roles;

      if (allowedRoles.includes(userRoles)) {
        req.user = decoded;
        next();
      } else {
        return res.status(403).json({ message: "Access forbidden" });
      }
    } catch (error) {
      return res.status(401).json({ message: "Invalid token" });
    }
  };
};
//logout util
// export function clearTokenCookie(res) {
//   res.clearCookie("token");
// }

export const clearTokenCookie = (res) => {
  res.cookie("token", "", {
    expires: new Date(0), // Set the cookie to an expired date
    httpOnly: true, // HttpOnly to prevent access from JavaScript
    secure: process.env.NODE_ENV === "production", // Set to true in production, false for development
    // sameSite: "strict", // Restrict cookie access to the same site
  });
};
// module.exports = { generateToken, verifyToken, clearTokenCookie };
