import dotenv from "dotenv";
import connectDB from "./db/index.js";
import { app } from "./app.js";

dotenv.config({
  path: "./env",
});
connectDB()
  .then(() => {
    app.on("error", (error) => {
      console.log("ERR:", error);
      throw error;
    });
    app.listen(process.env.PORT || 8000, () => {
      console.log("App listening on port", process.env.PORT);
    });
  })
  .catch((err) => {
    console.log("Mpngo db connection failed", err);
  });
