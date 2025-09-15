const express = require("express");
const router = express.Router();
const Note = require("../models/Note");
const crypto = require("crypto");

async function verifyTurnstile(token) {
  if (!token) return false;
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) {
    console.error("TURNSTILE_SECRET_KEY is not set in environment variables");
    return false;
  }
  const urlencoded = new URLSearchParams();
  urlencoded.append("secret", secret);
  urlencoded.append("response", token);
  try {
    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        body: urlencoded,
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      }
    );
    if (!response.ok) {
      console.error(
        `Turnstile verification failed with status: ${response.status}`
      );
      return false;
    }
    const data = await response.json();
    console.log(`Turnstile verification response: ${JSON.stringify(data)}`);
    return data.success || false;
  } catch (err) {
    console.error("Error verifying Turnstile token:", err);
    return false;
  }
}

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(password || "")
    .digest("hex");
}

router.get("/:noteId", async (req, res) => {
  const token = req.query["cf-turnstile-response"];
  try {
    if (!token || !(await verifyTurnstile(token))) {
      return res.status(403).json({ error: "CAPTCHA validation failed" });
    }
    const note = await Note.findOne({ noteId: req.params.noteId });
    if (!note) {
      return res.json({ content: "", requiresPassword: false });
    }
    res.json({
      content: note.password ? "" : note.content,
      requiresPassword: !!note.password,
    });
  } catch (err) {
    console.error("Error in GET /notes/:noteId:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/:noteId", async (req, res) => {
  const { content, password, "cf-turnstile-response": token } = req.body;
  try {
    if (!(await verifyTurnstile(token)))
      return res.status(403).json({ error: "CAPTCHA validation failed" });
    let note = await Note.findOne({ noteId: req.params.noteId });
    if (note) {
      if (note.password && note.password !== hashPassword(password)) {
        return res.status(401).json({ error: "Invalid password" });
      }
      note.content = content || "";
      await note.save();
      return res.json({ message: "saved" });
    } else {
      note = new Note({ noteId: req.params.noteId, content: content || "" });
      await note.save();
      res.json({ message: "created" });
    }
  } catch (err) {
    console.error("Error in POST /notes/:noteId:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/:noteId/set-password", async (req, res) => {
  const { password, "cf-turnstile-response": token } = req.body;
  try {
    if (!(await verifyTurnstile(token)))
      return res.status(403).json({ error: "CAPTCHA validation failed" });
    const note = await Note.findOne({ noteId: req.params.noteId });
    if (!note) return res.status(404).json({ error: "Note not found" });
    if (note.password)
      return res.status(400).json({ error: "Password already set" });
    if (!password)
      return res.status(400).json({ error: "Password is required" });
    note.password = hashPassword(password);
    await note.save();
    res.json({ message: "Password set" });
  } catch (err) {
    console.error("Error in POST /notes/:noteId/set-password:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/:noteId/verify", async (req, res) => {
  const { password, "cf-turnstile-response": token } = req.body;
  try {
    if (!(await verifyTurnstile(token)))
      return res.status(403).json({ error: "CAPTCHA validation failed" });
    const note = await Note.findOne({ noteId: req.params.noteId });
    if (!note) return res.status(404).json({ error: "Note not found" });
    if (!note.password) return res.json({ content: note.content });
    const hashed = hashPassword(password);
    if (hashed === note.password) {
      res.json({ content: note.content });
    } else {
      res.status(401).json({ error: "Invalid password" });
    }
  } catch (err) {
    console.error("Error in POST /notes/:noteId/verify:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

module.exports = router;
