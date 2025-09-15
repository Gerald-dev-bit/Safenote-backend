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

  const hasPassword = !!note.password; // Check if password exists
  if (!hasPassword) {
    return res.json({ content: note.content || "", hasPassword });
  }

  res.json({ hasPassword });
});

router.post("/:noteId/verify", async (req, res) => {
  const token = req.body["cf-turnstile-response"];
  if (!token || !(await verifyTurnstile(token, req.ip))) {
    return res.status(403).json({ error: "Invalid Turnstile token" });
  }

  const note = await Note.findOne({ noteId: req.params.noteId });
  if (!note) return res.status(404).json({ error: "Note not found" });

  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "Password required" });

  const hashed = hashPassword(password);
  if (hashed !== note.password) {
    return res.status(401).json({ error: "Invalid password" });
  }

  res.json({ content: note.content || "" });
});

router.post("/:noteId/set-password", async (req, res) => {
  const token = req.body["cf-turnstile-response"];
  if (!token || !(await verifyTurnstile(token, req.ip))) {
    return res.status(403).json({ error: "Invalid Turnstile token" });
  }

  const note = await Note.findOne({ noteId: req.params.noteId });
  if (!note) return res.status(404).json({ error: "Note not found" });

  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "Password required" });

  if (note.password) {
    return res.status(400).json({ error: "Password already set" });
  }

  note.password = hashPassword(password);
  await note.save();
  res.status(200).json({ message: "Password set successfully" });
});

router.post("/:oldId/rename", async (req, res) => {
  const token = req.body["cf-turnstile-response"];
  if (!token || !(await verifyTurnstile(token, req.ip))) {
    return res.status(403).json({ error: "Invalid Turnstile token" });
  }

  const { newId } = req.body;
  if (!newId) return res.status(400).json({ error: "New ID is required" });

  const oldNote = await Note.findOne({ noteId: req.params.oldId });
  if (!oldNote) return res.status(404).json({ error: "Note not found" });

  const existingNote = await Note.findOne({ noteId: newId });
  if (existingNote) return res.status(400).json({ error: "ID already in use" });

  oldNote.noteId = newId.toLowerCase();
  await oldNote.save();
  res.status(200).json({ message: "Note renamed successfully", newId });
});

module.exports = router;
