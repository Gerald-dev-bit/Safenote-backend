//routes/notes.js
const express = require("express");
const router = express.Router();
const Note = require("../models/Note");
const crypto = require("crypto");

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

// New: Turnstile verification endpoint (optimized with timeout)
router.post("/verify-turnstile", async (req, res) => {
  console.time("turnstile-verify"); // Profiling start
  const { token } = req.body;
  if (!token) {
    console.timeEnd("turnstile-verify");
    return res.status(400).json({ error: "Token required" });
  }

  try {
    // Add timeout to prevent hangs (5s max for external fetch)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const verifyResponse = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          secret: process.env.TURNSTILE_SECRET_KEY,
          response: token,
        }),
        signal: controller.signal,
      }
    );

    clearTimeout(timeoutId);

    const verifyData = await verifyResponse.json();
    if (verifyData.success) {
      console.timeEnd("turnstile-verify");
      res.json({ success: true });
    } else {
      console.timeEnd("turnstile-verify");
      res.status(400).json({ error: "Verification failed" });
    }
  } catch (error) {
    console.timeEnd("turnstile-verify");
    if (error.name === "AbortError") {
      console.error("Turnstile fetch timeout");
      return res.status(408).json({ error: "Request timeout" });
    }
    console.error("Turnstile verification error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

router.get("/:noteId", async (req, res) => {
  console.time("notes-get"); // Profiling start
  try {
    // Optimized: Use lean() for faster read (no hydration)
    let note = await Note.findOne({ noteId: req.params.noteId }).lean();
    if (!note) {
      // Idempotent: Create empty note on GET
      note = new Note({ noteId: req.params.noteId, content: "" });
      await note.save();
      // Re-fetch lean version
      note = await Note.findOne({ noteId: req.params.noteId }).lean();
    }

    const requiresPassword = !!note.password;
    if (!requiresPassword) {
      console.timeEnd("notes-get");
      return res.json({ content: note.content || "", requiresPassword });
    }

    console.timeEnd("notes-get");
    res.json({ requiresPassword });
  } catch (error) {
    console.timeEnd("notes-get");
    console.error("GET note error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/:noteId", async (req, res) => {
  console.time("notes-post"); // Profiling start
  try {
    let note = await Note.findOne({ noteId: req.params.noteId }).lean();
    if (!note) {
      note = new Note({ noteId: req.params.noteId });
      await note.save();
    }

    const { content, password } = req.body;

    if (note.password) {
      if (!password || hashPassword(password) !== note.password) {
        console.timeEnd("notes-post");
        return res.status(401).json({ error: "Invalid password" });
      }
    }

    // Update (fetch full doc for save)
    note = await Note.findOne({ noteId: req.params.noteId });
    note.content = content || "";
    await note.save();

    console.timeEnd("notes-post");
    res.json({ message: "Note saved successfully" });
  } catch (error) {
    console.timeEnd("notes-post");
    console.error("POST note error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/:noteId/verify", async (req, res) => {
  console.time("notes-verify"); // Profiling start
  try {
    // Optimized: Use lean() for faster read
    const note = await Note.findOne({ noteId: req.params.noteId }).lean();
    if (!note) {
      console.timeEnd("notes-verify");
      return res.status(404).json({ error: "Note not found" });
    }

    const { password } = req.body;
    if (!password) {
      console.timeEnd("notes-verify");
      return res.status(400).json({ error: "Password required" });
    }

    const hashed = hashPassword(password);
    if (hashed !== note.password) {
      console.timeEnd("notes-verify");
      return res.status(401).json({ error: "Invalid password" });
    }

    console.timeEnd("notes-verify");
    res.json({ content: note.content || "" });
  } catch (error) {
    console.timeEnd("notes-verify");
    console.error("Verify password error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/:noteId/set-password", async (req, res) => {
  console.time("notes-set-password"); // Profiling start
  try {
    let note = await Note.findOne({ noteId: req.params.noteId }).lean();
    if (!note) {
      note = new Note({ noteId: req.params.noteId });
      await note.save();
    }

    const { password } = req.body;
    if (!password) {
      console.timeEnd("notes-set-password");
      return res.status(400).json({ error: "Password required" });
    }

    if (note.password) {
      console.timeEnd("notes-set-password");
      return res.status(400).json({ error: "Password already set" });
    }

    // Update (fetch full doc for save)
    note = await Note.findOne({ noteId: req.params.noteId });
    note.password = hashPassword(password);
    await note.save();

    console.timeEnd("notes-set-password");
    res.status(200).json({ message: "Password set successfully" });
  } catch (error) {
    console.timeEnd("notes-set-password");
    console.error("Set password error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/:oldId/rename", async (req, res) => {
  console.time("notes-rename"); // Profiling start
  try {
    const { newId } = req.body;
    if (!newId) {
      console.timeEnd("notes-rename");
      return res.status(400).json({ error: "New ID is required" });
    }

    // Optimized: Use lean() for checks
    const oldNote = await Note.findOne({ noteId: req.params.oldId }).lean();
    if (!oldNote) {
      console.timeEnd("notes-rename");
      return res.status(404).json({ error: "Note not found" });
    }

    const existingNote = await Note.findOne({
      noteId: newId.toLowerCase(),
    }).lean();
    if (existingNote) {
      console.timeEnd("notes-rename");
      return res.status(400).json({ error: "ID already in use" });
    }

    // Update (fetch full doc for save)
    const noteToUpdate = await Note.findOne({ noteId: req.params.oldId });
    noteToUpdate.noteId = newId.toLowerCase();
    await noteToUpdate.save();

    console.timeEnd("notes-rename");
    res.status(200).json({
      message: "Note renamed successfully",
      newId: newId.toLowerCase(),
    });
  } catch (error) {
    console.timeEnd("notes-rename");
    console.error("Rename error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
