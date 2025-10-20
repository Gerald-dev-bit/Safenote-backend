//server.js (full file with fix)
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

// Handle large payloads for notes (increased limit to 10MB)
app.use(express.json({ limit: "10mb" }));

const allowedOrigins = [
  "http://localhost:5173",
  "https://safenote-frontend.vercel.app",
  "https://www.safenote.xyz",
  "https://safenote.xyz",
];
app.use(
  cors({
    origin: allowedOrigins,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
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

// Use a custom key generator since ipKeyGenerator is from the utils subpath
const getClientIp = (req) => req.headers["cf-connecting-ip"] || req.ip;

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again later.",
  keyGenerator: (req) => getClientIp(req),
});

const passwordLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: "Too many password attempts from this IP, please try again later.",
  keyGenerator: (req) => getClientIp(req),
});

app.use("/api/notes/:noteId", generalLimiter);
app.use("/api/notes/:noteId/verify", passwordLimiter);
app.use("/api/notes/:noteId/set-password", passwordLimiter);
app.use("/api/notes/:oldId/rename", generalLimiter);
// New: Rate limit Turnstile verification (tightened to 5/min for abuse prevention)
app.use(
  "/api/verify-turnstile",
  rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message:
      "Too many verification attempts from this IP, please try again later.",
    keyGenerator: (req) => getClientIp(req),
  })
);

// New: Health endpoint for warm-up (simple DB ping)
app.get("/health", async (req, res) => {
  console.time("health-db-ping");
  try {
    // Minimal query to warm DB connection
    await mongoose.connection.db.admin().ping();
    console.timeEnd("health-db-ping");
    res.status(200).json({ status: "healthy" });
  } catch (err) {
    console.error("Health check failed:", err);
    res.status(500).json({ status: "unhealthy" });
  }
});

const connectDB = async (retries = 5, delayMs = 5000) => {
  while (retries > 0) {
    try {
      // Fixed: Removed bufferMaxEntries (unsupported by driver); kept bufferCommands: false for Mongoose buffering disable
      // Optimized for serverless: Limit pool to 1 connection (avoids leaks on Vercel)
      await mongoose.connect(process.env.MONGO_URI, {
        serverSelectionTimeoutMS: 5000,
        bufferCommands: false, // Disable Mongoose buffering
        minPoolSize: 1,
        maxPoolSize: 1, // Single connection for serverless efficiency
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

app.use("/api/notes", notesRouter); // Includes /verify-turnstile

app.use((err, req, res, next) => {
  console.error(err.stack);
  const isDev = process.env.NODE_ENV === "development";
  res
    .status(500)
    .json({ error: isDev ? err.message : "Internal server error" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`[${new Date().toISOString()}] Server running on port ${PORT}`)
);
