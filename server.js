const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const morgan = require("morgan");
const notesRouter = require("./routes/notes");
const fetch = require("node-fetch");

dotenv.config();

const app = express();
app.set("trust proxy", true);
app.use(helmet({ xFrameOptions: { action: "deny" } }));
app.use(morgan("combined"));
app.use(express.json());

const allowedOrigins = [
  "http://localhost:5173",
  "https://safenote-frontend.vercel.app",
  "https://www.safenote.xyz",
];
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "cf-turnstile-response"],
    credentials: true,
    optionsSuccessStatus: 200,
  })
);

app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(
    `[${timestamp}] Request: ${req.method} ${req.url} from ${
      req.headers.origin || "undefined"
    }`
  );
  next();
});

const getClientIp = (req) => req.headers["cf-connecting-ip"] || req.ip;

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests, try later.",
  keyGenerator: (req) => getClientIp(req),
});

const passwordLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: "Too many password attempts, try later.",
  keyGenerator: (req) => getClientIp(req),
});

app.use("/api/notes/:noteId", generalLimiter);
app.use("/api/notes/:noteId/verify", passwordLimiter);
app.use("/api/notes/:noteId/set-password", passwordLimiter);

const connectDB = async (retries = 5, delayMs = 5000) => {
  while (retries > 0) {
    try {
      await mongoose.connect(process.env.MONGO_URI, {
        serverSelectionTimeoutMS: 5000,
      });
      console.log("MongoDB connected");
      return;
    } catch (err) {
      console.error(`DB connect fail (${6 - retries}/5):`, err);
      retries--;
      if (retries === 0) process.exit(1);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
};
connectDB();

app.get("/health", (req, res) => res.status(200).json({ status: "OK" }));

app.use("/api/notes", notesRouter);

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error:
      process.env.NODE_ENV === "development" ? err.message : "Server error",
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server on port ${PORT}`));
