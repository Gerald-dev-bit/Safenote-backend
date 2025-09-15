const express = require("express");
const router = express.Router();
const Note = require("../models/Note");
const crypto = require("crypto");
const fetch = require("node-fetch");

async function verifyTurnstile(token) {
  if (!token) return false;
  const secret = process.env.TURNSTILE_SECRET_KEY;
  const urlencoded = new URLSearchParams();
  urlencoded.append("secret", secret);
  urlencoded.append("response", token);
  const res = await fetch(
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    {
      method: "POST",
      body: urlencoded,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    }
  );
  const data = await res.json();
  console.log(`Turnstile response: ${JSON.stringify(data)}`);
  return data.success;
}

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

router.get("/:noteId", async (req, res) => {
  const token = req.query["cf-turnstile-response"];
  if (!token || !(await verifyTurnstile(token))) {
    return res.status(403).json({ error: "CAPTCHA validation failed" });
  }
  try {
    const note = await Note.findOne({ noteId: req.params.noteId });
    if (!note) {
      return res.json({ content: "", requiresPassword: false });
    }
    res.json({
      content: note.password ? "" : note.content,
      requiresPassword: !!note.password,
    });
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/:noteId", async (req, res) => {
  const { content, password, "cf-turnstile-response": token } = req.body;
  if (!(await verifyTurnstile(token)))
    return res.status(403).json({ error: "CAPTCHA validation failed" });
  try {
    let note = await Note.findOne({ noteId: req.params.noteId });
    if (note) {
      if (note.password && note.password !== hashPassword(password || "")) {
        return res.status(401).json({ error: "Invalid password" });
      }
      note.content = content;
      await note.save();
      return res.json({ message: "saved" });
    } else {
      note = new Note({ noteId: req.params.noteId, content });
      await note.save();
      res.json({ message: "created" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/:noteId/set-password", async (req, res) => {
  const { password, "cf-turnstile-response": token } = req.body;
  if (!(await verifyTurnstile(token)))
    return res.status(403).json({ error: "CAPTCHA validation failed" });
  try {
    const note = await Note.findOne({ noteId: req.params.noteId });
    if (!note) return res.status(404).json({ error: "Note not found" });
    if (note.password)
      return res.status(400).json({ error: "Password already set" });
    note.password = hashPassword(password);
    await note.save();
    res.json({ message: "Password set" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/:noteId/verify", async (req, res) => {
  const { password, "cf-turnstile-response": token } = req.body;
  if (!(await verifyTurnstile(token)))
    return res.status(403).json({ error: "CAPTCHA validation failed" });
  try {
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
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
