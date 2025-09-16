const express = require("express");
const router = express.Router();
const Note = require("../models/Note");
const crypto = require("crypto");

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

router.get("/:noteId", async (req, res) => {
  try {
    let note = await Note.findOne({ noteId: req.params.noteId });
    if (!note) {
      note = new Note({ noteId: req.params.noteId, content: "" });
      await note.save();
    }

    const requiresPassword = !!note.password;
    res.json({ content: note.content || "", requiresPassword });
  } catch (error) {
    console.error("Error fetching note:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/:noteId", async (req, res) => {
  try {
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
  } catch (error) {
    console.error("Error saving note:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/:noteId/verify", async (req, res) => {
  try {
    const note = await Note.findOne({ noteId: req.params.noteId });
    if (!note) return res.status(404).json({ error: "Note not found" });

    const { password } = req.body;
    if (!password) return res.status(400).json({ error: "Password required" });

    const hashed = hashPassword(password);
    if (hashed !== note.password) {
      return res.status(401).json({ error: "Invalid password" });
    }

    res.json({ content: note.content || "" });
  } catch (error) {
    console.error("Error verifying password:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/:noteId/set-password", async (req, res) => {
  try {
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
  } catch (error) {
    console.error("Error setting password:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/:oldId/rename", async (req, res) => {
  try {
    const { newId } = req.body;
    if (!newId) return res.status(400).json({ error: "New ID is required" });

    const oldNote = await Note.findOne({ noteId: req.params.oldId });
    if (!oldNote) return res.status(404).json({ error: "Note not found" });

    const existingNote = await Note.findOne({ noteId: newId });
    if (existingNote)
      return res.status(400).json({ error: "ID already in use" });

    oldNote.noteId = newId.toLowerCase();
    await oldNote.save();
    res.status(200).json({ message: "Note renamed successfully", newId });
  } catch (error) {
    console.error("Error renaming note:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

module.exports = router;
