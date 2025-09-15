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
app.use(
  helmet({
    xFrameOptions: { action: "deny" }, // Keep X-Frame-Options, remove CSP as it's API-only
  })
);
app.use(morgan("combined"));
app.use(express.json());
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://safenote-frontend.vercel.app",
      "https://www.safenote.xyz",
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

// General rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again later.",
});

// Stricter limiter for password-related routes
const passwordLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: "Too many password attempts from this IP, please try again later.",
});

app.use("/api/notes/:noteId", generalLimiter);
app.use("/api/notes/:noteId/verify", passwordLimiter);
app.use("/api/notes/:noteId/set-password", passwordLimiter);
app.use("/api/notes/:oldId/rename", generalLimiter);

// Debug log for all requests
app.use((req, res, next) => {
  console.log(`Received request: ${req.method} ${req.url}`);
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
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
