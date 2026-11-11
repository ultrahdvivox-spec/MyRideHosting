
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

import { initializeApp, applicationDefault } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";

const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || "development";

// Firebase Admin initialization
initializeApp({
  credential: applicationDefault()
});

const auth = getAuth();
const db = getFirestore();

const app = express();

// Security headers
app.use(helmet());

// CORS: केवल निर्धारित वेबसाइटों को अनुमति
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(origin => origin.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Origin not allowed"));
  },
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "32kb" }));

// API rate limit
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

app.use("/api", apiLimiter);

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    project: "WHERE IS MY RIDE",
    environment: NODE_ENV,
    message: "Backend is running"
  });
});

// Firebase ID token verification
async function verifyFirebaseUser(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const match = header.match(/^Bearer (.+)$/);

    if (!match) {
      return res.status(401).json({
        success: false,
        message: "Authentication token required"
      });
    }

    const decoded = await auth.verifyIdToken(match[1], true);
    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired authentication token"
    });
  }
}

// Authenticated user check
app.get("/api/me", verifyFirebaseUser, (req, res) => {
  res.json({
    success: true,
    uid: req.user.uid,
    email: req.user.email || null
  });
});

// Unknown API route
app.use("/api", (req, res) => {
  res.status(404).json({
    success: false,
    message: "API route not found"
  });
});

// Error handler
app.use((error, req, res, next) => {
  console.error("Backend Error:", error.message);

  res.status(500).json({
    success: false,
    message: "Internal server error"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`WHERE IS MY RIDE backend listening on port ${PORT}`);
});

