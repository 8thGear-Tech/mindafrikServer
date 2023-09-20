import express from "express";
import session from "express-session";
import MongoStore from "connect-mongo";
import morgan from "morgan";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import globalErrorHandler from "./src/utils/globalErrorHandler.js";
import userRouter from "./src/router/userRoute.js";
import newsletterRouter from "./src/router/newsletterRoute.js";
import bookSessionRouter from "./src/router/bookSessionRouter.js";
import config from "./src/config/index.js";

dotenv.config({ path: "./configenv.env" });

const mongoURI = config.MONGODB_CONNECTION_URL;

mongoose
  .connect(mongoURI)
  .then(console.log("Database connection is established"))
  .catch((err) => console.log(err.message));
const port = config.PORT;
const app = express();

//express session

const store = MongoStore.create({
  mongoUrl: config.MONGODB_CONNECTION_URL, // Replace with your MongoDB connection URL
  // mongoUrl: "mongodb://localhost:27017/your_database_name", // Replace with your MongoDB connection URL
  // ttl: 14 * 24 * 60 * 60, // Session will expire after 14 days
});

const sess = {
  secret: "YOUR_SESSION_SECRET",
  resave: false,
  saveUninitialized: true,
  cookie: {},
  store: store,
};

if (process.env.NODE_ENV === "production") {
  sess.cookie.secure = true; // serve secure cookies
}

app.use(session(sess));

// Middleware
app.use(morgan("tiny"));
app.use(express.json());
// app.use(cors());

// Routes
app.use("/user", userRouter);
app.use("/subscriber", newsletterRouter);
app.use("/booking", bookSessionRouter);

app.use(
  cors({
    origin: "https://www.mindafrik.com",
    credentials: true,
    // methods: "GET,HEAD,PUT,PATCH,POST,DELETE", // Allow the necessary HTTP methods
    // preflightContinue: false,
    optionsSuccessStatus: 200, // Set the status code for successful OPTIONS requests
    // origin: "http://localhost:4000",
  })
);

// app.use((req, res, next) => {
//   res.setHeader("Access-Control-Allow-Origin", "https://www.mindafrik.com");
//   res.setHeader(
//     "Access-Control-Allow-Methods",
//     "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS,CONNECT,TRACE"
//   );
//   res.setHeader(
//     "Access-Control-Allow-Headers",
//     "Content-Type, Authorization, X-Content-Type-Options, Accept, X-Requested-With, Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
//   );
//   res.setHeader("Access-Control-Allow-Credentials", true);
//   res.setHeader("Access-Control-Allow-Private-Network", true);
//   //  Firefox caps this at 24 hours (86400 seconds). Chromium (starting in v76) caps at 2 hours (7200 seconds). The default value is 5 seconds.
//   res.setHeader("Access-Control-Max-Age", 7200);

//   next();
// });

// error handler
app.use(globalErrorHandler);

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
