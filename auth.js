import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { findByUsername } from "../utils/db.js";

const router = Router();
const JWT_SECRET = process.env.JWT_SECRET || "family-movie-watchlist-secret";

router.post("/login", async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required." });
  }

  const user = findByUsername(username);

  if (!user) {
    return res.status(401).json({ error: "Invalid username or password." });
  }

  let passwordIsValid = false;

  if (user.passwordHash) {
    passwordIsValid = await bcrypt.compare(password, user.passwordHash);
  }

  // Supports the provided seeded data if a plain-text password is supplied.
  if (!passwordIsValid && user._password) {
    passwordIsValid = password === user._password;
  }

  if (!passwordIsValid) {
    return res.status(401).json({ error: "Invalid username or password." });
  }

  const token = jwt.sign(
    {
      id: user.id,
      username: user.username,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  return res.status(200).json({ token });
});

export default router;
