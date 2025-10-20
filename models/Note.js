//models/Note.js (No changes needed; index already present)
const mongoose = require("mongoose");

const noteSchema = new mongoose.Schema({
  noteId: { type: String, required: true, unique: true, index: true },
  content: { type: String, default: "" },
  password: { type: String }, // Hashed if set
});

noteSchema.pre("save", function (next) {
  if (this.noteId) {
    this.noteId = this.noteId.toLowerCase();
  }
  next();
});

module.exports = mongoose.model("Note", noteSchema);
