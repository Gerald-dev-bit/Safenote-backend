const express = require("express");
const router = express.Router();
const fetch = require("node-fetch");

const verifyTurnstile = async (token) => {
  const secretKey = process.env.TURNSTILE_SECRET_KEY;
  const url = `https://challenges.cloudflare.com/turnstile/v0/siteverify`;

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret: secretKey, response: token }),
    });
    const data = await response.json();
    console.log("Turnstile response:", data);
    return data.success;
  } catch (error) {
    console.error("Turnstile verification error:", error);
    return false;
  }
};

const notes = {};

router.get("/:id", async (req, res) => {
  const noteId = req.params.id.toLowerCase();
  const token = req.query["cf-turnstile-response"];

  if (!token || !(await verifyTurnstile(token))) {
    return res.status(403).send("Unauthorized");
  }

  if (notes[noteId]) {
    res.json({
      content: notes[noteId].content,
      requiresPassword: notes[noteId].password !== undefined,
    });
  } else {
    res.json({ content: "", requiresPassword: false });
  }
});

router.post("/:id", async (req, res) => {
  const noteId = req.params.id.toLowerCase();
  const token = req.body["cf-turnstile-response"];

  if (!token || !(await verifyTurnstile(token))) {
    return res.status(403).send("Unauthorized");
  }

  const { content, password } = req.body;
  notes[noteId] = { content, password: password || undefined };
  res.sendStatus(200);
});

router.post("/:id/set-password", async (req, res) => {
  const noteId = req.params.id.toLowerCase();
  const token = req.body["cf-turnstile-response"];

  if (!token || !(await verifyTurnstile(token))) {
    return res.status(403).send("Unauthorized");
  }

  const { password } = req.body;
  if (notes[noteId] && notes[noteId].password) {
    return res.status(400).send("Password already set for this note");
  }
  if (notes[noteId]) {
    notes[noteId].password = password;
  } else {
    notes[noteId] = { content: notes[noteId]?.content || "", password };
  }
  res.sendStatus(200);
});

router.post("/:id/verify", async (req, res) => {
  const noteId = req.params.id.toLowerCase();
  const token = req.body["cf-turnstile-response"];

  if (!token || !(await verifyTurnstile(token))) {
    return res.status(403).send("Unauthorized");
  }

  const { password } = req.body;
  if (!notes[noteId] || !notes[noteId].password) {
    return res.status(400).send("No password set for this note");
  }
  if (notes[noteId].password !== password) {
    return res.status(401).send("Incorrect password");
  }
  res.json({ content: notes[noteId].content });
});

module.exports = router;
