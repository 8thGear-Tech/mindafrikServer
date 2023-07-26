import development from "../config/development.js";
import production from "../config/production.js";

import dotenv from "dotenv";

dotenv.config({ path: "./configenv.env" });

const environment = process.env.NODE_ENV;

let config;
if (!environment) throw new Error("No environment setup on the SERVER!!!");

console.log(`Server setup to ${environment}!!!`);

if (environment.trim() === "production") {
  config = { ...production };
}
if (environment.trim() === "development") {
  config = { ...development };
}

export default config;
