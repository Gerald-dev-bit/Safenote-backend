// routes/notes.js
const express = require("express");
const bcrypt = require("bcryptjs");
const Note = require("../models/Note");

const router = express.Router();

// GET /api/notes/:noteId - Get note content (create if not exists; check password if set)
router.get("/:noteId", async (req, res) => {
  const noteId = req.params.noteId.toLowerCase();
  try {
    let note = await Note.findOne({ noteId });
    if (!note) {
      // Create empty note if not exists
      note = new Note({ noteId, content: "" });
      await note.save();
      return res.json({ requiresPassword: false, content: note.content });
    }
    // If password set, don't return content yet
    if (note.password) {
      return res.json({ requiresPassword: true });
    }
    return res.json({ requiresPassword: false, content: note.content });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/notes/:noteId/verify - Verify password and get content
router.post("/:noteId/verify", async (req, res) => {
  const noteId = req.params.noteId.toLowerCase();
  const { password } = req.body;
  try {
    const note = await Note.findOne({ noteId });
    if (!note) {
      return res.status(404).json({ error: "Note not found" });
    }
    if (!note.password) {
      return res.json({ content: note.content }); // No password needed
    }
    const isMatch = await bcrypt.compare(password, note.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Incorrect password" });
    }
    res.json({ content: note.content });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/notes/:noteId - Update content (requires password if set)
router.post("/:noteId", async (req, res) => {
  const noteId = req.params.noteId.toLowerCase();
  const { content, password } = req.body; // Password optional, but required if set
  try {
    const note = await Note.findOne({ noteId });
    if (!note) {
      return res.status(404).json({ error: "Note not found" });
    }
    if (note.password) {
      if (!password)
        return res.status(401).json({ error: "Password required" });
      const isMatch = await bcrypt.compare(password, note.password);
      if (!isMatch)
        return res.status(401).json({ error: "Incorrect password" });
    }
    note.content = content || ""; // Allow blank saves
    await note.save();
    res.json({ message: "Note updated" });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/notes/:noteId/set-password - Set password
router.post("/:noteId/set-password", async (req, res) => {
  const noteId = req.params.noteId.toLowerCase();
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "Password required" });
  try {
    const note = await Note.findOne({ noteId });
    if (!note) {
      return res.status(404).json({ error: "Note not found" });
    }
    const salt = await bcrypt.genSalt(10);
    note.password = await bcrypt.hash(password, salt);
    await note.save();
    res.json({ message: "Password set" });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/notes/:oldId/rename - Rename note (check uniqueness)
router.post("/:oldId/rename", async (req, res) => {
  const oldId = req.params.oldId.toLowerCase();
  let { newId } = req.body;
  newId = newId.toLowerCase();
  if (!newId || newId === oldId)
    return res.status(400).json({ error: "Invalid new ID" });
  try {
    const existing = await Note.findOne({ noteId: newId });
    if (existing) return res.status(409).json({ error: "ID already taken" });
    const oldNote = await Note.findOne({ noteId: oldId });
    if (!oldNote) return res.status(404).json({ error: "Note not found" });
    const newNote = new Note({
      noteId: newId,
      content: oldNote.content,
      password: oldNote.password,
    });
    await newNote.save();
    await Note.deleteOne({ noteId: oldId });
    res.json({ message: "Note renamed", newId });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/notes/check-availability - Check if noteId is available (for rename)
router.post("/check-availability", async (req, res) => {
  let { noteId } = req.body;
  noteId = noteId.toLowerCase();
  try {
    const exists = await Note.findOne({ noteId });
    res.json({ available: !exists });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
