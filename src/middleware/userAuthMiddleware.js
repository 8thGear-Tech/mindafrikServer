// // middleware/roleAuthMiddleware.js

import jwt from "jsonwebtoken";
// import config from "../config/index.js"; // Adjust the import path based on your project structure

// const roleAuthMiddleware = (allowedRoles) => {
//   return (req, res, next) => {
//     const accessToken = req.headers.authorization;

//     if (!accessToken || !accessToken.startsWith("Bearer ")) {
//       return res.status(401).json({ message: "Invalid access token format" });
//     }

//     const token = accessToken.slice(7); // Remove the "Bearer " prefix

//     try {
//       const decodedToken = jwt.verify(token, config.jwt_secret_key);
//       const userRole = decodedToken.userRole;

//       if (allowedRoles.includes(userRole)) {
//         next();
//       } else {
//         res.status(403).json({ message: "Unauthorized" });
//       }
//     } catch (error) {
//       res.status(401).json({ message: "Invalid access token" });
//     }
//   };
// };

// export default roleAuthMiddleware;

// // // middleware/roleAuthMiddleware.js
// // import jwt from "jsonwebtoken";
// // import config from "../config/index.js";

// // const roleAuthMiddleware = (allowedRoles) => {
// //   return (req, res, next) => {
// //     // Assuming you have an "authorization" header containing the access token
// //     const accessToken = req.headers.authorization;

// //     if (!accessToken) {
// //       return res.status(401).json({ message: "Access token missing" });
// //     }

// //     try {
// //       // Decode the token to get the payload
// //       const decodedToken = jwt.verify(accessToken, config.jwt_secret_key);

// //       // Assuming your payload contains the user's role as "userRole"
// //       const userRole = decodedToken.userRole;
// //       //   const userRole = decodedToken.payload.userRole;

// //       // Check if the user's role is included in the allowed roles
// //       if (allowedRoles.includes(userRole)) {
// //         // If the user's role is allowed, proceed to the next middleware (or route handler)
// //         next();
// //       } else {
// //         // If the user's role is not allowed, respond with a 403 Forbidden status
// //         res.status(403).json({ message: "Unauthorized" });
// //       }
// //     } catch (error) {
// //       // If the token is invalid, respond with a 401 Unauthorized status
// //       res.status(401).json({ message: "Invalid access token" });
// //     }
// //   };
// // };

// // export default roleAuthMiddleware;

// const checkUserRole = (allowedRoles) => {
//   return (req, res, next) => {
//     const userRoles = req.user.roles;

//     if (allowedRoles.some((role) => userRoles.includes(role))) {
//       next();
//     } else {
//       res.status(403).json({ message: "Unauthorized" });
//     }
//   };
// };

// export default checkUserRole;

const verifyToken = (req, res, next) => {
  const accessToken = req.headers["authorization"];
  if (!accessToken) {
    return res.status(403).json({ message: "Access token not provided" });
  }

  jwt.verify(accessToken, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid token" });
    }

    req.user = decoded;

    // Check if the user has the required roles
    const allowedRoles = ["Counsellee", "Counsellor", "Admin"]; // Define your roles
    if (allowedRoles.includes(req.user.roles)) {
      next();
    } else {
      return res.status(403).json({ message: "Access forbidden" });
    }
  });
};

export default verifyToken;
