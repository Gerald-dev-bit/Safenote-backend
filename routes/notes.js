const express = require("express");
const router = express.Router();
const Note = require("../models/Note");
const crypto = require("crypto");

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

router.get("/:noteId", async (req, res) => {
  let note = await Note.findOne({ noteId: req.params.noteId });
  if (!note) {
    note = new Note({ noteId: req.params.noteId, content: "" });
    await note.save();
  }

  const requiresPassword = !!note.password;
  if (!requiresPassword) {
    return res.json({ content: note.content || "", requiresPassword });
  }

  res.json({ requiresPassword });
});

router.post("/:noteId", async (req, res) => {
  let note = await Note.findOne({ noteId: req.params.noteId });
  if (!note) {
    note = new Note({ noteId: req.params.noteId });
  }

  const { content, password } = req.body;

  if (note.password) {
    if (!password || hashPassword(password) !== note.password) {
      return res.status(401).json({ error: "Invalid password" });
    }
  }

  note.content = content || "";
  await note.save();

  res.json({ message: "Note saved successfully" });
});

router.post("/:noteId/verify", async (req, res) => {
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
  let note = await Note.findOne({ noteId: req.params.noteId });
  if (!note) {
    note = new Note({ noteId: req.params.noteId });
    await note.save();
  }

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
