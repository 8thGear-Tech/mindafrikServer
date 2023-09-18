import express from "express";
import morgan from "morgan";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
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

// Middleware
app.use(morgan("tiny"));
app.use(express.json());
app.use(cors());
app.use(cookieParser());

// Routes
app.use("/user", userRouter);
app.use("/subscriber", newsletterRouter);
app.use("/booking", bookSessionRouter);

app.use(
  cors({
    origin: "https://www.mindafrik.com",
    // origin: "http://localhost:4000",
    credentials: true, // Make sure this option is set
  })
);

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "https://www.mindafrik.com");
  res.header("Access-Control-Allow-Credentials", true);
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept"
  );
  next();
});
// error handler
app.use(globalErrorHandler);

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
