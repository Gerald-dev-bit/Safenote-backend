const express = require("express");
const router = express.Router();
const Note = require("../models/Note");
const crypto = require("crypto");
const fetch = require("node-fetch");

async function verifyTurnstile(token, ip) {
  try {
    const formData = new FormData();
    formData.append("secret", process.env.TURNSTILE_SECRET_KEY);
    formData.append("response", token);
    if (ip) formData.append("remoteip", ip);

    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        body: formData,
      }
    );

    const data = await response.json();
    console.log("Turnstile verify response:", data); // Log for debugging
    return data.success;
  } catch (error) {
    console.error("Turnstile verification error:", error);
    return false;
  }
}

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

router.get("/:noteId", async (req, res) => {
  const token = req.query["cf-turnstile-response"];
  if (!token || !(await verifyTurnstile(token, req.ip))) {
    return res.status(403).json({ error: "Invalid Turnstile token" });
  }

  const note = await Note.findOne({ noteId: req.params.noteId });
  if (!note) return res.status(404).json({ error: "Note not found" });

  const hasPassword = !!note.hashedPassword;
  if (!hasPassword) {
    const content = note.content;
    delete notes[req.params.noteId];
    return res.json({ content, hasPassword });
  }

  res.json({ hasPassword });
});

router.post("/api/notes/:noteId/verify", async (req, res) => {
  const token = req.body["cf-turnstile-response"];
  if (!token || !(await verifyTurnstile(token, req.ip))) {
    return res.status(403).json({ error: "Invalid Turnstile token" });
  }

  const note = notes[req.params.noteId];
  if (!note) return res.status(404).json({ error: "Note not found" });

  const { password } = req.body;
  const hashed = crypto.createHash("sha256").update(password).digest("hex");
  if (hashed !== note.hashedPassword) {
    return res.status(401).json({ error: "Invalid password" });
  }

  // Self-destruct after successful verify
  const content = note.content;
  delete notes[req.params.noteId];
  res.json({ content });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
