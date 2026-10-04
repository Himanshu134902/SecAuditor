import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { runSecurityAudit } from "./src/services/scanner.js";
import Scan from "./src/models/scan.js";
import mongoose from "mongoose";
import rateLimit from "express-rate-limit";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// In-memory fallback if MongoDB isn't active
let inMemoryHistory = [];

// 1. Health endpoint
app.get("/api/health", (req, res) => {
  res.json({ 
    status: "ok", 
    mongoConnected: mongoose.connection.readyState === 1 
  });
});

// 2. Scan History endpoint
app.get("/api/history", async (req, res) => {
  try {
    if (mongoose.connection.readyState === 1) {
      const dbScans = await Scan.find().sort({ scannedAt: -1 }).limit(10);
      return res.json(dbScans);
    }
    // Fallback if Mongo is down
    return res.json(inMemoryHistory);
  } catch (err) {
    console.error("Error retrieving history:", err.message);
    return res.json(inMemoryHistory);
  }
});

// 3. Scan Target endpoint
app.post("/api/scan", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ error: "URL is required" });
    }

    const report = await runSecurityAudit(url);

    // Save to Mongo if available, else save to memory
    if (mongoose.connection.readyState === 1) {
      try {
        const saved = await Scan.create(report);
        return res.json(saved);
      } catch (dbErr) {
        console.warn("DB save failed, using memory:", dbErr.message);
      }
    }

    // In-memory log
    const entry = { ...report, _id: Date.now().toString() };
    inMemoryHistory.unshift(entry);
    if (inMemoryHistory.length > 10) inMemoryHistory.pop();

    res.json(entry);
  } catch (error) {
    console.error("Scan error:", error.message);
    res.status(500).json({
      error: "Failed to audit target URL",
      details: error.message
    });
  }
});

// Connect to MongoDB gracefully (timeout after 2s so it doesn't hang)
const MONGO_URI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/secauditor";

const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15-minute window
  max: 20, // max 20 audits per window
  message: {
    error: "Scan rate limit reached. Please wait a few minutes before scanning again."
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Pass limiter middleware to the scan endpoint
app.post("/api/scan", scanLimiter, async (req, res) => {
  // ... existing scan logic
});

mongoose
  .connect(MONGO_URI, { serverSelectionTimeoutMS: 2000 })
  .then(() => console.log("MongoDB connected successfully."))
  .catch((err) => {
    console.warn("MongoDB connection failed:", err.message);
    console.warn("Running in memory fallback mode (scans will be retained in RAM).");
  })
  .finally(() => {
    app.listen(PORT, () => {
      console.log(`SecAuditor backend running on http://localhost:${PORT}`);
    });
  });