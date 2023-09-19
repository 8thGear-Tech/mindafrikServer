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
app.use(cors());

// Routes
app.use("/user", userRouter);
app.use("/subscriber", newsletterRouter);
app.use("/booking", bookSessionRouter);

app.use(
  cors({
    origin: "https://www.mindafrik.com",
    credentials: true,
    // origin: "http://localhost:4000",
  })
);

// error handler
app.use(globalErrorHandler);

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
