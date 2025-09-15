const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const morgan = require("morgan");
const notesRouter = require("./routes/notes");

dotenv.config();

const app = express();
app.set("trust proxy", true);
app.use(
  helmet({
    xFrameOptions: { action: "deny" },
  })
);
app.use(morgan("combined"));
app.use(express.json());

const allowedOrigins = [
  "http://localhost:5173",
  "https://safenote-frontend.vercel.app",
  "https://www.safenote.xyz",
];
app.use(
  cors({
    origin: allowedOrigins,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "cf-turnstile-response"],
    credentials: true,
    optionsSuccessStatus: 200,
  })
);

app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] Received request: ${req.method} ${req.url}`);
  console.log(`[${timestamp}] Request headers:`, req.headers);
  console.log(
    `[${timestamp}] CORS Origin: ${req.headers.origin || "undefined"}`
  );
  next();
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again later.",
  keyGenerator: (req) => req.headers["cf-connecting-ip"] || req.ip,
});
const passwordLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: "Too many password attempts from this IP, please try again later.",
  keyGenerator: (req) => req.headers["cf-connecting-ip"] || req.ip,
});

app.use("/api/notes/:noteId", generalLimiter);
app.use("/api/notes/:noteId/verify", passwordLimiter);
app.use("/api/notes/:noteId/set-password", passwordLimiter);
app.use("/api/notes/:oldId/rename", generalLimiter);

const connectDB = async (retries = 5, delayMs = 5000) => {
  while (retries > 0) {
    try {
      await mongoose.connect(process.env.MONGO_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });
      console.log("MongoDB connected");
      return;
    } catch (err) {
      console.error(
        `MongoDB connection attempt failed (${6 - retries}/5):`,
        err
      );
      retries--;
      if (retries === 0) process.exit(1);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
};
connectDB();

app.use("/api/notes", notesRouter);

app.use((err, req, res, next) => {
  console.error(err.stack);
  const isDev = process.env.NODE_ENV === "development";
  res.status(500).json({ error: isDev ? err.message : "Server error" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`[${new Date().toISOString()}] Server running on port ${PORT}`)
);
