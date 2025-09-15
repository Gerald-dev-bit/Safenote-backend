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
    xFrameOptions: { action: "deny" }, // Keep X-Frame-Options, remove CSP as it's API-only
  })
);
app.use(morgan("combined"));
app.use(express.json());

// Enhanced CORS configuration
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
    optionsSuccessStatus: 200, // Some legacy browsers choke on 204
  })
);

// Single logging middleware with detailed output
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] Received request: ${req.method} ${req.url}`);
  console.log(`[${timestamp}] Request headers:`, req.headers);
  console.log(
    `[${timestamp}] CORS Origin: ${req.headers.origin || "undefined"}`
  );
  next();
});

// General rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again later.",
  keyGenerator: (req) => req.headers["cf-connecting-ip"] || req.ip,
});

// Stricter limiter for password-related routes
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

// Fallback CORS handler for OPTIONS and undefined origin
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
    res.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    res.header(
      "Access-Control-Allow-Headers",
      "Content-Type,Authorization,cf-turnstile-response"
    );
    res.header("Access-Control-Allow-Credentials", "true");
  } else if (req.method === "OPTIONS") {
    console.log(
      `[${timestamp}] Handling OPTIONS preflight with no origin, allowing default`
    );
    res.header("Access-Control-Allow-Origin", allowedOrigins[0]); // Fallback for debugging
    res.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    res.header(
      "Access-Control-Allow-Headers",
      "Content-Type,Authorization,cf-turnstile-response"
    );
    res.header("Access-Control-Allow-Credentials", "true");
    return res.status(200).end();
  }
  next();
});

// Connect to MongoDB with retry logic
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

// Routes
app.use("/api/notes", notesRouter);

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  const isDev = process.env.NODE_ENV === "development";
  res.status(500).json({ error: isDev ? err.message : "Server error" });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`[${new Date().toISOString()}] Server running on port ${PORT}`)
);
