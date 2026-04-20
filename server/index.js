/**
 * SECURE MESSAGING SYSTEM - Express + MongoDB Backend
 *
 * This is a standalone Express server that you run locally alongside the Next.js frontend.
 * It uses MongoDB for persistent storage and Socket.io for real-time messaging.
 *
 * SETUP INSTRUCTIONS:
 * 1. Install MongoDB locally or use MongoDB Atlas
 * 2. cd server && npm install
 * 3. Create .env file with MONGODB_URI and JWT_SECRET
 * 4. npm start
 *
 * The Next.js frontend will connect to this server at http://localhost:5000
 */

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const server = http.createServer(app);

// Socket.io setup with CORS
const io = new Server(server, {
  cors: {
    origin: ["http://localhost:3000", "http://127.0.0.1:3000"],
    methods: ["GET", "POST"],
    credentials: true,
  },
});

// Middleware
app.use(
  cors({
    origin: ["http://localhost:3000", "http://127.0.0.1:3000"],
    credentials: true,
  })
);
app.use(express.json({ limit: "50mb" }));

// MongoDB Connection
const MONGODB_URI =
  process.env.MONGODB_URI || "mongodb://localhost:27017/secure_messaging";
const JWT_SECRET =
  process.env.JWT_SECRET || "your-super-secret-jwt-key-change-in-production";

mongoose
  .connect(MONGODB_URI)
  .then(() => console.log("[SERVER] Connected to MongoDB"))
  .catch((err) => console.error("[SERVER] MongoDB connection error:", err));

// ============================================
// MONGOOSE SCHEMAS
// ============================================

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, index: true },
  passwordHash: { type: String, required: true },
  salt: { type: String, required: true },
  publicKey: { type: String, required: true }, // ECDH public key (base64)
  signaturePublicKey: { type: String, required: true }, // ECDSA public key (base64)
  createdAt: { type: Date, default: Date.now },
});

const MessageSchema = new mongoose.Schema(
  {
    senderId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    receiverId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    ciphertext: { type: String, required: false }, // Base64 encoded (optional for file messages)
    iv: { type: String, required: true }, // Base64 encoded (12 bytes for AES-GCM)
    nonce: { type: String, required: true }, // Base64 encoded (replay protection)
    signature: { type: String, required: true }, // Base64 encoded ECDSA signature
    timestamp: { type: Number, required: true, index: true },
    sequenceNumber: { type: Number, required: true },
    isFile: { type: Boolean, default: false },
    fileName: { type: String },
    fileId: { type: String },
  },
  { timestamps: true }
);

// Compound index for efficient message queries
MessageSchema.index({ senderId: 1, receiverId: 1, timestamp: -1 });

const FileSchema = new mongoose.Schema(
  {
    senderId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    receiverId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    fileName: { type: String, required: true },
    encryptedData: { type: String, required: true }, // Base64 encoded encrypted file
    iv: { type: String, required: true },
    nonce: { type: String, required: true },
    signature: { type: String, required: true },
    timestamp: { type: Number, required: true },
    fileSize: { type: Number, required: true },
  },
  { timestamps: true }
);

const KeyExchangeSchema = new mongoose.Schema(
  {
    senderId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    receiverId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    type: {
      type: String,
      enum: ["INIT", "RESPONSE", "CONFIRM", "KEY_EXCHANGE_AUTO"],
      required: true,
    },
    publicKey: { type: String, required: false }, // Ephemeral ECDH public key (optional for auto exchanges)
    signature: { type: String, required: true },
    nonce: { type: String, required: true },
    timestamp: { type: Number, required: true },
    processed: { type: Boolean, default: false },
  },
  { timestamps: true }
);

// Index for efficient key exchange queries
KeyExchangeSchema.index({ receiverId: 1, processed: 1 });

const SecurityLogSchema = new mongoose.Schema({
  eventType: {
    type: String,
    enum: [
      "AUTH_SUCCESS",
      "AUTH_FAILURE",
      "REGISTRATION",
      "KEY_EXCHANGE_INIT",
      "KEY_EXCHANGE_RESPONSE",
      "KEY_EXCHANGE_COMPLETE",
      "KEY_EXCHANGE_AUTO",
      "MESSAGE_SENT",
      "MESSAGE_RECEIVED",
      "DECRYPTION_FAILURE",
      "REPLAY_DETECTED",
      "SIGNATURE_INVALID",
      "TIMESTAMP_INVALID",
      "FILE_UPLOADED",
      "FILE_DOWNLOADED",
    ],
    required: true,
  },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  targetUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  ipAddress: { type: String },
  userAgent: { type: String },
  details: { type: mongoose.Schema.Types.Mixed },
  timestamp: { type: Date, default: Date.now },
});

SecurityLogSchema.index({ timestamp: -1 });
SecurityLogSchema.index({ eventType: 1, timestamp: -1 });

const User = mongoose.model("User", UserSchema);
const Message = mongoose.model("Message", MessageSchema);
const File = mongoose.model("File", FileSchema);
const KeyExchange = mongoose.model("KeyExchange", KeyExchangeSchema);
const SecurityLog = mongoose.model("SecurityLog", SecurityLogSchema);

// ============================================
// SECURITY LOGGING HELPER
// ============================================

async function logSecurityEvent(eventType, data, req = null) {
  try {
    const logEntry = new SecurityLog({
      eventType,
      userId: data.userId,
      targetUserId: data.targetUserId,
      ipAddress: req?.ip || req?.connection?.remoteAddress || "unknown",
      userAgent: req?.headers?.["user-agent"] || "unknown",
      details: data.details || {},
      timestamp: new Date(),
    });
    await logEntry.save();
    console.log(
      `[SECURITY] ${eventType}:`,
      JSON.stringify(data.details || {}).substring(0, 100)
    );
  } catch (err) {
    console.error("[SECURITY] Failed to log event:", err.message);
  }
}

// ============================================
// PASSWORD HASHING (PBKDF2)
// ============================================

function hashPassword(password, salt = null) {
  if (!salt) {
    salt = crypto.randomBytes(32).toString("base64");
  }
  const hash = crypto
    .pbkdf2Sync(password, salt, 100000, 64, "sha512")
    .toString("base64");
  return { hash, salt };
}

function verifyPassword(password, hash, salt) {
  const { hash: computedHash } = hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(computedHash));
}

// ============================================
// JWT AUTHENTICATION MIDDLEWARE
// ============================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      logSecurityEvent(
        "AUTH_FAILURE",
        { details: { reason: "Invalid token" } },
        req
      );
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
}

// ============================================
// REPLAY PROTECTION
// ============================================

const processedNonces = new Map(); // In production, use Redis
const NONCE_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes

function isNonceValid(nonce) {
  if (processedNonces.has(nonce)) {
    return false; // Replay detected
  }
  processedNonces.set(nonce, Date.now());
  return true;
}

// Clean up old nonces periodically
setInterval(() => {
  const now = Date.now();
  for (const [nonce, timestamp] of processedNonces.entries()) {
    if (now - timestamp > NONCE_EXPIRY_MS) {
      processedNonces.delete(nonce);
    }
  }
}, 60000); // Clean every minute

// ============================================
// AUTH ROUTES
// ============================================

// Register new user
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password, publicKey, signaturePublicKey } = req.body;

    if (!username || !password || !publicKey || !signaturePublicKey) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Check if username exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      await logSecurityEvent(
        "REGISTRATION",
        {
          details: { username, success: false, reason: "Username exists" },
        },
        req
      );
      return res.status(409).json({ error: "Username already exists" });
    }

    // Hash password
    const { hash, salt } = hashPassword(password);

    // Create user
    const user = new User({
      username,
      passwordHash: hash,
      salt,
      publicKey,
      signaturePublicKey,
    });

    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id.toString(), username: user.username },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    await logSecurityEvent(
      "REGISTRATION",
      {
        userId: user._id,
        details: { username, success: true },
      },
      req
    );

    res.status(201).json({
      user: {
        id: user._id.toString(),
        username: user.username,
        publicKey: user.publicKey,
        signaturePublicKey: user.signaturePublicKey,
      },
      token,
    });
  } catch (err) {
    console.error("[AUTH] Registration error:", err);
    res.status(500).json({ error: "Registration failed" });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    const user = await User.findOne({ username });
    if (!user) {
      await logSecurityEvent(
        "AUTH_FAILURE",
        {
          details: { username, reason: "User not found" },
        },
        req
      );
      return res.status(401).json({ error: "Invalid credentials" });
    }

    if (!verifyPassword(password, user.passwordHash, user.salt)) {
      await logSecurityEvent(
        "AUTH_FAILURE",
        {
          userId: user._id,
          details: { username, reason: "Invalid password" },
        },
        req
      );
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user._id.toString(), username: user.username },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    await logSecurityEvent(
      "AUTH_SUCCESS",
      {
        userId: user._id,
        details: { username },
      },
      req
    );

    res.json({
      user: {
        id: user._id.toString(),
        username: user.username,
        publicKey: user.publicKey,
        signaturePublicKey: user.signaturePublicKey,
      },
      token,
    });
  } catch (err) {
    console.error("[AUTH] Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// ============================================
// USER ROUTES
// ============================================

// Get all users (for user list)
app.get("/api/users", authenticateToken, async (req, res) => {
  try {
    const users = await User.find(
      { _id: { $ne: req.user.userId } },
      { passwordHash: 0, salt: 0 }
    );

    res.json({
      users: users.map((u) => ({
        id: u._id.toString(),
        username: u.username,
        publicKey: u.publicKey,
        signaturePublicKey: u.signaturePublicKey,
      })),
    });
  } catch (err) {
    console.error("[USERS] Error fetching users:", err);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

// Get user by ID
app.get("/api/users/:id", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.id, {
      passwordHash: 0,
      salt: 0,
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      id: user._id.toString(),
      username: user.username,
      publicKey: user.publicKey,
      signaturePublicKey: user.signaturePublicKey,
    });
  } catch (err) {
    console.error("[USERS] Error fetching user:", err);
    res.status(500).json({ error: "Failed to fetch user" });
  }
});

// ============================================
// KEY EXCHANGE ROUTES
// ============================================

// Initiate or respond to key exchange
app.post("/api/key-exchange", authenticateToken, async (req, res) => {
  try {
    const { receiverId, type, publicKey, signature, nonce, timestamp } =
      req.body;

    // Validate timestamp (within 5 minutes)
    const now = Date.now();
    if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
      await logSecurityEvent(
        "TIMESTAMP_INVALID",
        {
          userId: req.user.userId,
          targetUserId: receiverId,
          details: { type, timeDiff: now - timestamp },
        },
        req
      );
      return res.status(400).json({ error: "Timestamp out of valid range" });
    }

    // Check nonce for replay
    if (!isNonceValid(nonce)) {
      await logSecurityEvent(
        "REPLAY_DETECTED",
        {
          userId: req.user.userId,
          targetUserId: receiverId,
          details: { type, nonce },
        },
        req
      );
      return res.status(400).json({ error: "Replay attack detected" });
    }

    const keyExchange = new KeyExchange({
      senderId: req.user.userId,
      receiverId,
      type,
      publicKey,
      signature,
      nonce,
      timestamp,
    });

    await keyExchange.save();

    await logSecurityEvent(
      type === "INIT"
        ? "KEY_EXCHANGE_INIT"
        : type === "KEY_EXCHANGE_AUTO"
        ? "KEY_EXCHANGE_AUTO"
        : "KEY_EXCHANGE_RESPONSE",
      {
        userId: req.user.userId,
        targetUserId: receiverId,
        details: { type },
      },
      req
    );

    // Notify recipient via Socket.io (skip for automatic exchanges to avoid noise)
    if (type !== "KEY_EXCHANGE_AUTO") {
      io.to(receiverId).emit("key-exchange", {
        id: keyExchange._id.toString(),
        senderId: req.user.userId,
        type,
        publicKey,
        signature,
        nonce,
        timestamp,
      });
    }

    res.status(201).json({
      id: keyExchange._id.toString(),
      message:
        type === "KEY_EXCHANGE_AUTO"
          ? "Automatic key exchange logged"
          : "Key exchange message sent",
    });
  } catch (err) {
    console.error("[KEY-EXCHANGE] Error:", err);
    res.status(500).json({ error: "Key exchange failed" });
  }
});

// Get pending key exchanges for user
app.get("/api/key-exchange", authenticateToken, async (req, res) => {
  try {
    const { partnerId } = req.query;

    const query = {
      receiverId: req.user.userId,
      processed: false,
    };

    if (partnerId) {
      query.senderId = partnerId;
    }

    const exchanges = await KeyExchange.find(query).sort({ timestamp: 1 });

    res.json(
      exchanges.map((e) => ({
        id: e._id.toString(),
        senderId: e.senderId.toString(),
        receiverId: e.receiverId.toString(),
        type: e.type,
        publicKey: e.publicKey,
        signature: e.signature,
        nonce: e.nonce,
        timestamp: e.timestamp,
      }))
    );
  } catch (err) {
    console.error("[KEY-EXCHANGE] Error fetching:", err);
    res.status(500).json({ error: "Failed to fetch key exchanges" });
  }
});

// Mark key exchange as processed
app.patch("/api/key-exchange/:id", authenticateToken, async (req, res) => {
  try {
    await KeyExchange.findByIdAndUpdate(req.params.id, { processed: true });
    res.json({ message: "Key exchange marked as processed" });
  } catch (err) {
    console.error("[KEY-EXCHANGE] Error updating:", err);
    res.status(500).json({ error: "Failed to update key exchange" });
  }
});

// ============================================
// MESSAGE ROUTES
// ============================================

// Send encrypted message
app.post("/api/messages", authenticateToken, async (req, res) => {
  try {
    const {
      receiverId,
      ciphertext,
      iv,
      nonce,
      signature,
      timestamp,
      sequenceNumber,
      isFile,
      fileName,
      fileId,
    } = req.body;

    // Validate timestamp
    const now = Date.now();
    if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
      await logSecurityEvent(
        "TIMESTAMP_INVALID",
        {
          userId: req.user.userId,
          targetUserId: receiverId,
          details: { timeDiff: now - timestamp },
        },
        req
      );
      return res.status(400).json({ error: "Timestamp out of valid range" });
    }

    // Check nonce for replay
    if (!isNonceValid(nonce)) {
      await logSecurityEvent(
        "REPLAY_DETECTED",
        {
          userId: req.user.userId,
          targetUserId: receiverId,
          details: { nonce },
        },
        req
      );
      return res.status(400).json({ error: "Replay attack detected" });
    }

    const message = new Message({
      senderId: req.user.userId,
      receiverId,
      ciphertext,
      iv,
      nonce,
      signature,
      timestamp,
      sequenceNumber,
      isFile: isFile || false,
      fileName,
      fileId,
    });

    await message.save();

    await logSecurityEvent(
      "MESSAGE_SENT",
      {
        userId: req.user.userId,
        targetUserId: receiverId,
        details: { messageId: message._id.toString(), isFile },
      },
      req
    );

    // Real-time notification via Socket.io
    io.to(receiverId).emit("new-message", {
      id: message._id.toString(),
      senderId: req.user.userId,
      ciphertext,
      iv,
      nonce,
      signature,
      timestamp,
      sequenceNumber,
      isFile,
      fileName,
      fileId,
    });

    res.status(201).json({
      id: message._id.toString(),
      message: "Message sent",
    });
  } catch (err) {
    console.error("[MESSAGES] Error sending:", err);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// Get messages between two users
app.get("/api/messages", authenticateToken, async (req, res) => {
  try {
    const { partnerId, since } = req.query;

    if (!partnerId) {
      return res.status(400).json({ error: "Partner ID required" });
    }

    const query = {
      $or: [
        { senderId: req.user.userId, receiverId: partnerId },
        { senderId: partnerId, receiverId: req.user.userId },
      ],
    };

    if (since) {
      query.timestamp = { $gt: Number.parseInt(since) };
    }

    const messages = await Message.find(query)
      .sort({ timestamp: 1 })
      .limit(100);

    res.json({
      messages: messages.map((m) => ({
        id: m._id.toString(),
        senderId: m.senderId.toString(),
        receiverId: m.receiverId.toString(),
        ciphertext: m.ciphertext,
        iv: m.iv,
        nonce: m.nonce,
        signature: m.signature,
        timestamp: m.timestamp,
        sequenceNumber: m.sequenceNumber,
        isFile: m.isFile,
        fileName: m.fileName,
        fileId: m.fileId,
      })),
    });
  } catch (err) {
    console.error("[MESSAGES] Error fetching:", err);
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});

// ============================================
// FILE ROUTES
// ============================================

// Upload encrypted file
app.post("/api/files", authenticateToken, async (req, res) => {
  try {
    const {
      receiverId,
      fileName,
      encryptedData,
      iv,
      nonce,
      signature,
      timestamp,
      fileSize,
    } = req.body;

    // Validate required fields
    if (
      !receiverId ||
      !fileName ||
      !encryptedData ||
      !iv ||
      !nonce ||
      !signature ||
      !timestamp ||
      !fileSize
    ) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Validate timestamp
    const now = Date.now();
    if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
      return res.status(400).json({ error: "Timestamp out of valid range" });
    }

    if (!isNonceValid(nonce)) {
      await logSecurityEvent(
        "REPLAY_DETECTED",
        {
          userId: req.user.userId,
          targetUserId: receiverId,
          details: { nonce, operation: "file_upload" },
        },
        req
      );
      return res.status(400).json({ error: "Replay attack detected" });
    }

    const file = new File({
      senderId: req.user.userId,
      receiverId,
      fileName,
      encryptedData,
      iv,
      nonce,
      signature,
      timestamp,
      fileSize,
    });

    await file.save();

    // Create a message entry for the file
    const fileMessage = new Message({
      senderId: req.user.userId,
      receiverId,
      ciphertext: "",
      iv,
      nonce,
      signature,
      timestamp,
      sequenceNumber: timestamp,
      isFile: true,
      fileName,
      fileId: file._id.toString(),
    });

    await fileMessage.save();

    await logSecurityEvent(
      "FILE_UPLOADED",
      {
        userId: req.user.userId,
        targetUserId: receiverId,
        details: { fileId: file._id.toString(), fileName, fileSize },
      },
      req
    );

    res.status(201).json({
      id: file._id.toString(),
      message: "File uploaded",
    });
  } catch (err) {
    console.error("[FILES] Error uploading:", err);
    console.error("[FILES] Error details:", err.message, err.stack);
    res
      .status(500)
      .json({ error: "Failed to upload file", details: err.message });
  }
});

// Download encrypted file
app.get("/api/files/:id", authenticateToken, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);

    if (!file) {
      return res.status(404).json({ error: "File not found" });
    }

    // Verify user is sender or receiver
    if (
      file.senderId.toString() !== req.user.userId &&
      file.receiverId.toString() !== req.user.userId
    ) {
      return res.status(403).json({ error: "Access denied" });
    }

    await logSecurityEvent(
      "FILE_DOWNLOADED",
      {
        userId: req.user.userId,
        details: { fileId: file._id.toString(), fileName: file.fileName },
      },
      req
    );

    res.json({
      id: file._id.toString(),
      senderId: file.senderId.toString(),
      receiverId: file.receiverId.toString(),
      fileName: file.fileName,
      encryptedData: file.encryptedData,
      iv: file.iv,
      nonce: file.nonce,
      signature: file.signature,
      timestamp: file.timestamp,
      fileSize: file.fileSize,
    });
  } catch (err) {
    console.error("[FILES] Error downloading:", err);
    res.status(500).json({ error: "Failed to download file" });
  }
});

// ============================================
// SECURITY LOGS ROUTE
// ============================================

app.get("/api/security-logs", authenticateToken, async (req, res) => {
  try {
    const { limit = 100, eventType } = req.query;

    const query = {};
    if (eventType) {
      query.eventType = eventType;
    }

    const logs = await SecurityLog.find(query)
      .sort({ timestamp: -1 })
      .limit(Number.parseInt(limit));

    res.json(
      logs.map((l) => ({
        id: l._id.toString(),
        eventType: l.eventType,
        userId: l.userId?.toString(),
        targetUserId: l.targetUserId?.toString(),
        ipAddress: l.ipAddress,
        userAgent: l.userAgent,
        details: l.details,
        timestamp: l.timestamp,
      }))
    );
  } catch (err) {
    console.error("[SECURITY-LOGS] Error fetching:", err);
    res.status(500).json({ error: "Failed to fetch security logs" });
  }
});

// ============================================
// SOCKET.IO REAL-TIME EVENTS
// ============================================

io.on("connection", (socket) => {
  console.log("[SOCKET] Client connected:", socket.id);

  // User joins their personal room for notifications
  socket.on("join", (userId) => {
    socket.join(userId);
    console.log(`[SOCKET] User ${userId} joined their room`);
  });

  // Typing indicators
  socket.on("typing", ({ userId, partnerId }) => {
    io.to(partnerId).emit("user-typing", { userId });
  });

  socket.on("stop-typing", ({ userId, partnerId }) => {
    io.to(partnerId).emit("user-stopped-typing", { userId });
  });

  socket.on("disconnect", () => {
    console.log("[SOCKET] Client disconnected:", socket.id);
  });
});

// ============================================
// START SERVER
// ============================================

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`[SERVER] Secure Messaging Backend running on port ${PORT}`);
  console.log(`[SERVER] MongoDB: ${MONGODB_URI}`);
  console.log("[SERVER] Socket.io enabled for real-time messaging");
});
