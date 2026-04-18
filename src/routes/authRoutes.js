import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/User.js";

const router = express.Router();

// POST /api/auth/register
router.post("/register", async (req, res) => {
  // - Validate input
  // - Check if user exists
  // - Hash password
  // - Save user
  // - Return user (without password)
  try {
    const { name, email, password } = req.body;
    // Validate & Check if user exists
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: "User already exists" });

    // Hash password & Save
    const hashedPassword = await bcrypt.hash(password, 8);
    user = new User({ name, email, password: hashedPassword });
    await user.save();

    // Return user (without password)
    const userObj = user.toObject();
    delete userObj.password;
    res.status(201).json(userObj);
  } catch (e) {
    res.status(400).send(e);
  }
});

// POST /api/auth/login
router.post("/login", async (req, res) => {
  // - Find user
  // - Compare password
  // - Generate JWT
  // - Return token
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    res.json({ user, token });
  } catch (e) {
    res.status(500).send();
  }
});

export default router;
