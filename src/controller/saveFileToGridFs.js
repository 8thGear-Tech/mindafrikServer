import config from "../../src/config/index.js";
import dotenv from "dotenv";

import { MongoClient } from "mongodb";
import { Readable } from "stream";

dotenv.config({ path: "./configenv.env" });

// Connection URL
const uri = config.MONGODB_CONNECTION_URL;
const dbName = "mindafrikDB";
const client = new MongoClient(uri, { useUnifiedTopology: true });

// Function to save file to GridFS
async function saveFileToGridFS(file) {
  try {
    await client.connect();
    const database = client.db(dbName);
    const bucket = new mongodb.GridFSBucket(database);

    const stream = Readable.from(file.buffer); // Assuming file.buffer contains the file data
    const uploadStream = bucket.openUploadStream(file.originalname);
    stream.pipe(uploadStream);

    return new Promise((resolve, reject) => {
      uploadStream.on("finish", () => {
        resolve(uploadStream.id);
      });

      uploadStream.on("error", (error) => {
        reject(error);
      });
    });
  } catch (error) {
    throw error;
  } finally {
    client.close();
  }
}

export default saveFileToGridFS;
