require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const Razorpay = require("razorpay");

const { initializeApp, getApps } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const {
  getFirestore,
  FieldValue
} = require("firebase-admin/firestore");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const PROJECT_ID = "myridebhilwara-45652";
const ADMIN_UID = "cT4sWJpjCKf6KL7oT4UnbliYDgp2";

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  throw new Error("Invalid PORT");
}

if (getApps().length === 0) {
  initializeApp({ projectId: PROJECT_ID });
}

const db = getFirestore();

app.disable("x-powered-by");
app.use(helmet());

const allowedOrigins = new Set([
  "https://myridebhilwara-45652.web.app",
  "https://myridebhilwara-45652.firebaseapp.com"
]);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) {
      return callback(null, true);
    }
    return callback(null, false);
  },
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: false,
  maxAge: 600
}));

// Razorpay webhook needs the original raw body.
// Keep this route BEFORE express.json().
app.post(
  "/payment/razorpay/webhook",
  express.raw({ type: "application/json", limit: "100kb" }),
  async (req, res) => {
    try {
      const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
      const signature = req.headers["x-razorpay-signature"];

      if (!secret) {
        return res.status(503).json({
          success: false,
          error: "Razorpay webhook is not configured"
        });
      }

      if (!signature || !Buffer.isBuffer(req.body)) {
        return res.status(400).json({
          success: false,
          error: "Invalid webhook request"
        });
      }

      const expected = crypto
        .createHmac("sha256", secret)
        .update(req.body)
        .digest("hex");

      const a = Buffer.from(signature);
      const b = Buffer.from(expected);

      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return res.status(401).json({
          success: false,
          error: "Invalid webhook signature"
        });
      }

      const event = JSON.parse(req.body.toString("utf8"));

      if (event.event === "payment.captured") {
        const payment = event.payload?.payment?.entity;

        if (payment?.order_id && payment?.id) {
          const query = await db.collection("Booking")
            .where("razorpayOrderId", "==", payment.order_id)
            .limit(1)
            .get();

          if (!query.empty) {
            const ref = query.docs[0].ref;

            await db.runTransaction(async transaction => {
              const snap = await transaction.get(ref);
              if (!snap.exists) return;

              const booking = snap.data();

              if (
                booking.status === "Completed" &&
                booking.razorpayOrderId === payment.order_id &&
                Number(payment.amount) === Math.round(Number(booking.fare) * 100)
              ) {
                transaction.update(ref, {
                  paymentMethod: "Razorpay",
                  paymentStatus: "Paid",
                  razorpayPaymentId: payment.id,
                  paymentVerifiedAt: FieldValue.serverTimestamp()
                });
              }
            });
          }
        }
      }

      return res.status(200).json({ success: true });

    } catch (error) {
      console.error("Webhook error:", error.code || error.message);
      return res.status(500).json({
        success: false,
        error: "Webhook processing failed"
      });
    }
  }
);

app.use(express.json({ limit: "10kb" }));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-8",
  legacyHeaders: false
}));

const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

function fail(message, status = 400) {
  const error = new Error(message);
  error.statusCode = status;
  throw error;
}

function validId(value) {
  return typeof value === "string" &&
    /^[A-Za-z0-9_-]{1,150}$/.test(value);
}

function validText(value, max = 250) {
  return typeof value === "string" &&
    value.trim().length > 0 &&
    value.trim().length <= max;
}

function onlyKeys(body, allowed) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    fail("Invalid request body");
  }

  if (Object.keys(body).some(key => !allowed.includes(key))) {
    fail("Unexpected request field");
  }
}

function sendError(res, error) {
  const status = error.statusCode || 500;

  if (status >= 500) {
    console.error("API error:", error.code || error.message);
  }

  return res.status(status).json({
    success: false,
    error: status >= 500 ? "Internal server error" : error.message
  });
}

async function requireFirebaseAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const match = header.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    return res.status(401).json({
      success: false,
      error: "Firebase login token required"
    });
  }

  try {
    const decoded = await getAuth().verifyIdToken(match[1], true);

    req.user = {
      uid: decoded.uid,
      email: decoded.email || ""
    };

    return next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      error: "Invalid or expired Firebase token"
    });
  }
}

function requireAdmin(req, res, next) {
  if (req.user.uid !== ADMIN_UID) {
    return res.status(403).json({
      success: false,
      error: "Admin permission required"
    });
  }
  next();
}

function getBookingRef(id) {
  if (!validId(id)) fail("Invalid Booking ID");
  return db.collection("Booking").doc(id);
}

async function getDriver(transaction, uid) {
  const ref = db.collection("Drivers").doc(uid);
  const snap = await transaction.get(ref);

  if (!snap.exists) fail("Driver Profile नहीं मिली।", 403);

  const driver = snap.data();

  if (driver.verified !== true || driver.active !== true) {
    fail("Driver Verified और Active नहीं है।", 403);
  }

  if (
    !validText(driver.name, 100) ||
    !validText(driver.phone, 20) ||
    !validText(driver.vehicleNumber, 30) ||
    !validText(driver.vehicleModel, 100)
  ) {
    fail("Driver Profile अधूरी है।", 403);
  }

  return driver;
}

function driverFields(driver, uid, email) {
  return {
    driverUid: uid,
    driverEmail: email || driver.email || "",
    driverName: driver.name,
    driverPhone: driver.phone,
    vehicleNumber: driver.vehicleNumber,
    vehicleModel: driver.vehicleModel
  };
}

function makeRazorpay() {
  const keyId = process.env.RAZORPAY_KEY_ID;
  const keySecret = process.env.RAZORPAY_KEY_SECRET;

  if (!keyId || !keySecret) return null;

  return new Razorpay({
    key_id: keyId,
    key_secret: keySecret
  });
}

function safeEqualHex(a, b) {
  if (
    typeof a !== "string" ||
    typeof b !== "string" ||
    !/^[a-f0-9]+$/i.test(a) ||
    !/^[a-f0-9]+$/i.test(b)
  ) return false;

  const x = Buffer.from(a, "hex");
  const y = Buffer.from(b, "hex");

  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// ======================================================
// 1. HEALTH
// ======================================================

app.get("/health", (req, res) => {
  res.json({
    success: true,
    project: "WHERE IS MY RIDE",
    projectId: PROJECT_ID,
    message: "Backend is running",
    razorpayConfigured: Boolean(
      process.env.RAZORPAY_KEY_ID &&
      process.env.RAZORPAY_KEY_SECRET
    )
  });
});

// ======================================================
// 2. AUTH CHECK
// ======================================================

app.get(
  "/auth-check",
  strictLimiter,
  requireFirebaseAuth,
  (req, res) => {
    res.json({
      success: true,
      authenticated: true,
      uid: req.user.uid
    });
  }
);

// ======================================================
// 3. CUSTOMER BOOKING
// POST /customer/booking
// POST /hotel/booking (customer QR booking alias)
// ======================================================

async function createCustomerBooking(req, res) {
  try {
    onlyKeys(req.body, [
      "pickup",
      "destination",
      "vehicleType",
      "hotelId"
    ]);

    const pickup = req.body.pickup?.trim();
    const destination = req.body.destination?.trim();
    const vehicleType = req.body.vehicleType;

    if (!validText(pickup) || !validText(destination)) {
      fail("Pickup और Destination भरें।");
    }

    if (pickup.toLowerCase() === destination.toLowerCase()) {
      fail("Pickup और Destination अलग-अलग चुनें।");
    }

    if (!["Bike", "Car", "Auto", "E-Rickshaw"].includes(vehicleType)) {
      fail("Invalid vehicle type");
    }

    const uid = req.user.uid;
    const profileSnap = await db.collection("CustomerProfiles")
      .doc(uid)
      .get();

    if (!profileSnap.exists) {
      fail("पहले Customer Profile सेव करें।", 403);
    }

    const profile = profileSnap.data();

    if (
      !validText(profile.name, 100) ||
      !validText(profile.phone, 20)
    ) {
      fail("Customer Profile अधूरी है।", 403);
    }

    let hotel = null;
    let hotelId = null;

    if (req.body.hotelId !== undefined) {
      hotelId = req.body.hotelId;

      if (!validId(hotelId)) fail("Invalid Hotel ID");

      const hotelSnap = await db.collection("HotelPublic")
        .doc(hotelId)
        .get();

      if (!hotelSnap.exists || hotelSnap.data().active !== true) {
        fail("Hotel Partner उपलब्ध या Active नहीं है।", 403);
      }

      hotel = hotelSnap.data();

      if (!validText(hotel.name, 150)) {
        fail("Hotel Name उपलब्ध नहीं है।");
      }
    }

    const ref = db.collection("Booking").doc();
    const privateRef = db.collection("BookingPrivate").doc(ref.id);

    const data = {
      customerUid: uid,
      customerName: profile.name,
      city: "Bhilwara",
      pickup,
      destination,
      vehicleType,
      status: "Pending",
      fare: 0,

      driverUid: "",
      driverEmail: "",
      driverName: "",
      driverPhone: "",
      vehicleNumber: "",
      vehicleModel: "",

      driverLat: null,
      driverLng: null,

      createdAt: FieldValue.serverTimestamp(),
      privacyMigrated: true
    };

    if (hotel) {
      data.hotelId = hotelId;
      data.hotelName = hotel.name;
      data.bookingSource = "HotelQR";
    }

    const batch = db.batch();

    batch.create(ref, data);

    batch.create(privateRef, {
      customerUid: uid,
      customerPhone: profile.phone,
      customerEmail: req.user.email,
      createdAt: FieldValue.serverTimestamp()
    });

    await batch.commit();

    return res.status(201).json({
      success: true,
      bookingId: ref.id,
      status: "Pending",
      message: "Booking सफलतापूर्वक भेज दी गई।"
    });

  } catch (error) {
    return sendError(res, error);
  }
}

app.post(
  "/customer/booking",
  strictLimiter,
  requireFirebaseAuth,
  createCustomerBooking
);

app.post(
  "/hotel/booking",
  strictLimiter,
  requireFirebaseAuth,
  createCustomerBooking
);

// ======================================================
// 4. CUSTOMER CANCEL
// POST /customer/cancel
// ======================================================

app.post(
  "/customer/cancel",
  requireFirebaseAuth,
  async (req, res) => {
    try {
      onlyKeys(req.body, ["bookingId"]);

      const ref = getBookingRef(req.body.bookingId);

      await db.runTransaction(async transaction => {
        const snap = await transaction.get(ref);

        if (!snap.exists) fail("Booking नहीं मिली।", 404);

        const booking = snap.data();

        if (booking.customerUid !== req.user.uid) {
          fail("यह Booking आपके नाम पर नहीं है।", 403);
        }

        if (booking.status !== "Pending") {
          fail("केवल Pending Booking Cancel हो सकती है।", 409);
        }

        transaction.update(ref, {
          status: "Cancelled",
          cancelledAt: FieldValue.serverTimestamp()
        });
      });

      res.json({ success: true, status: "Cancelled" });

    } catch (error) {
      sendError(res, error);
    }
  }
);

// ======================================================
// 5. DRIVER ACCEPT
// POST /driver/accept
// ======================================================

app.post(
  "/driver/accept",
  strictLimiter,
  requireFirebaseAuth,
  async (req, res) => {
    try {
      onlyKeys(req.body, ["bookingId"]);

      const ref = getBookingRef(req.body.bookingId);

      await db.runTransaction(async transaction => {
        const snap = await transaction.get(ref);

        if (!snap.exists) fail("Booking नहीं मिली।", 404);

        const booking = snap.data();

        if (booking.status !== "Pending" || booking.driverUid !== "") {
          fail("यह Booking पहले ही Assign हो चुकी है।", 409);
        }

        const driver = await getDriver(transaction, req.user.uid);

        transaction.update(ref, {
          status: "Accepted",
          ...driverFields(driver, req.user.uid, req.user.email),
          acceptedAt: FieldValue.serverTimestamp()
        });
      });

      res.json({ success: true, status: "Accepted" });

    } catch (error) {
      sendError(res, error);
    }
  }
);

// ======================================================
// 6. ADMIN ASSIGN
// POST /admin/assign
// ======================================================

app.post(
  "/admin/assign",
  requireFirebaseAuth,
  requireAdmin,
  async (req, res) => {
    try {
      onlyKeys(req.body, ["bookingId", "driverUid"]);

      if (!validId(req.body.driverUid)) fail("Invalid Driver UID");

      const ref = getBookingRef(req.body.bookingId);

      await db.runTransaction(async transaction => {
        const snap = await transaction.get(ref);

        if (!snap.exists) fail("Booking नहीं मिली।", 404);

        const booking = snap.data();

        if (
          !["Pending", "Accepted"].includes(booking.status) ||
          booking.driverUid
        ) {
          fail("यह Booking Assign नहीं की जा सकती।", 409);
        }

        const driver = await getDriver(transaction, req.body.driverUid);

        transaction.update(ref, {
          status: "Accepted",
          ...driverFields(driver, req.body.driverUid, driver.email || ""),
          acceptedAt: FieldValue.serverTimestamp()
        });
      });

      res.json({ success: true, status: "Accepted" });

    } catch (error) {
      sendError(res, error);
    }
  }
);

// ======================================================
// 7. ADMIN REJECT
// POST /admin/reject
// ======================================================

app.post(
  "/admin/reject",
  requireFirebaseAuth,
  requireAdmin,
  async (req, res) => {
    try {
      onlyKeys(req.body, ["bookingId", "reason"]);

      if (
        req.body.reason !== undefined &&
        !validText(req.body.reason, 250)
      ) {
        fail("Invalid rejection reason");
      }

      const ref = getBookingRef(req.body.bookingId);

      await db.runTransaction(async transaction => {
        const snap = await transaction.get(ref);

        if (!snap.exists) fail("Booking नहीं मिली।", 404);

        const booking = snap.data();

        if (booking.status !== "Pending" || booking.driverUid) {
          fail("केवल Unassigned Pending Booking Reject हो सकती है।", 409);
        }

        transaction.update(ref, {
          status: "Rejected",
          rejectionReason: req.body.reason || "",
          rejectedAt: FieldValue.serverTimestamp()
        });
      });

      res.json({ success: true, status: "Rejected" });

    } catch (error) {
      sendError(res, error);
    }
  }
);

// ======================================================
// 8. DRIVER ARRIVED
// POST /driver/arrived
// ======================================================

app.post(
  "/driver/arrived",
  requireFirebaseAuth,
  async (req, res) => {
    try {
      onlyKeys(req.body, ["bookingId"]);

      const ref = getBookingRef(req.body.bookingId);

      await db.runTransaction(async transaction => {
        const snap = await transaction.get(ref);
        const driverRef = db.collection("Drivers").doc(req.user.uid);
        const driverSnap = await transaction.get(driverRef);

        if (!snap.exists) fail("Booking नहीं मिली।", 404);
        if (!driverSnap.exists) fail("Driver Profile नहीं मिली।", 403);

        const booking = snap.data();
        const driver = driverSnap.data();

        if (driver.verified !== true || driver.active !== true) {
          fail("Driver Verified और Active नहीं है।", 403);
        }

        if (booking.driverUid !== req.user.uid) {
          fail("यह Booking आपके नाम पर नहीं है।", 403);
        }

        if (booking.status !== "Accepted") {
          fail("Booking Accepted नहीं है।", 409);
        }

        transaction.update(ref, {
          status: "Arrived",
          arrivedAt: FieldValue.serverTimestamp()
        });
      });

      res.json({ success: true, status: "Arrived" });

    } catch (error) {
      sendError(res, error);
    }
  }
);

// ======================================================
// 9. CUSTOMER ARRIVAL CONFIRMATION
// POST /customer/confirm-arrival
// ======================================================

app.post(
  "/customer/confirm-arrival",
  requireFirebaseAuth,
  async (req, res) => {
    try {
      onlyKeys(req.body, ["bookingId"]);

      const ref = getBookingRef(req.body.bookingId);

      await db.runTransaction(async transaction => {
        const snap = await transaction.get(ref);

        if (!snap.exists) fail("Booking नहीं मिली।", 404);

        const booking = snap.data();

        if (booking.customerUid !== req.user.uid) {
          fail("यह Booking आपके नाम पर नहीं है।", 403);
        }

        if (booking.status !== "Arrived") {
          fail("Driver के Arrived होने के बाद ही Confirm करें।", 409);
        }

        transaction.update(ref, {
          customerStartConfirmed: true,
          customerConfirmedAt: FieldValue.serverTimestamp()
        });
      });

      res.json({
        success: true,
        customerStartConfirmed: true
      });

    } catch (error) {
      sendError(res, error);
    }
  }
);

// ======================================================
// 10. CUSTOMER RIDE OTP
// POST /customer/ride-otp
// OTP is returned to the authenticated customer.
// SMS is not sent by this endpoint.
// ======================================================

app.post(
  "/customer/ride-otp",
  otpLimiter,
  requireFirebaseAuth,
  async (req, res) => {
    try {
      onlyKeys(req.body, ["bookingId"]);

      const ref = getBookingRef(req.body.bookingId);
      const privateRef = db.collection("BookingPrivate")
        .doc(req.body.bookingId);

      const otp = String(crypto.randomInt(100000, 1000000));
      const otpHash = crypto.createHash("sha256")
        .update(otp)
        .digest("hex");

      await db.runTransaction(async transaction => {
        const snap = await transaction.get(ref);
        const privateSnap = await transaction.get(privateRef);

        if (!snap.exists || !privateSnap.exists) {
          fail("Booking या Private Record नहीं मिली।", 404);
        }

        const booking = snap.data();

        if (booking.customerUid !== req.user.uid) {
          fail("यह Booking आपके नाम पर नहीं है।", 403);
        }

        if (
          booking.status !== "Arrived" ||
          booking.customerStartConfirmed !== true
        ) {
          fail("पहले Driver Arrival Confirm करें।", 409);
        }

        transaction.set(privateRef, {
          rideOtpHash: otpHash,
          rideOtpExpiresAt: Date.now() + 5 * 60 * 1000,
          rideOtpAttempts: 0,
          rideOtpVerified: false
        }, { merge: true });
      });

      res.json({
        success: true,
        otp,
        expiresInSeconds: 300,
        message: "OTP Driver को स्वयं दिखाएँ।"
      });

    } catch (error) {
      sendError(res, error);
    }
  }
);

// ======================================================
// 11. DRIVER VERIFY OTP
// POST /driver/verify-otp
// ======================================================

app.post(
  "/driver/verify-otp",
  otpLimiter,
  requireFirebaseAuth,
  async (req, res) => {
    try {
      onlyKeys(req.body, ["bookingId", "otp"]);

      if (!/^[0-9]{6}$/.test(req.body.otp || "")) {
        fail("6 digit OTP आवश्यक है।");
      }

      const ref = getBookingRef(req.body.bookingId);
      const privateRef = db.collection("BookingPrivate")
        .doc(req.body.bookingId);

      const submittedHash = crypto.createHash("sha256")
        .update(req.body.otp)
        .digest("hex");

      const result = await db.runTransaction(async transaction => {
        const snap = await transaction.get(ref);
        const privateSnap = await transaction.get(privateRef);

        if (!snap.exists || !privateSnap.exists) {
          fail("Booking नहीं मिली।", 404);
        }

        const booking = snap.data();
        const privateData = privateSnap.data();

        if (booking.driverUid !== req.user.uid) {
          fail("यह Booking आपके नाम पर नहीं है।", 403);
        }

        if (
          booking.status !== "Arrived" ||
          booking.customerStartConfirmed !== true
        ) {
          fail("Customer Confirmation जरूरी है।", 409);
        }

        if (privateData.rideOtpVerified === true) {
          fail("OTP पहले ही Verify हो चुका है।", 409);
        }

        if (
          !privateData.rideOtpHash ||
          !privateData.rideOtpExpiresAt ||
          Date.now() > privateData.rideOtpExpiresAt
        ) {
          fail("OTP समाप्त हो गया है। नया OTP लें।", 410);
        }

        const attempts = Number(privateData.rideOtpAttempts || 0);

        if (attempts >= 5) {
          fail("OTP attempts समाप्त हो गए।", 429);
        }

        if (privateData.rideOtpHash !== submittedHash) {
          transaction.update(privateRef, {
            rideOtpAttempts: attempts + 1
          });
          return false;
        }

        transaction.update(privateRef, {
          rideOtpVerified: true,
          rideOtpVerifiedAt: FieldValue.serverTimestamp()
        });

        return true;
      });

      if (!result) {
        return res.status(400).json({
          success: false,
          error: "OTP गलत है।"
        });
      }

      res.json({
        success: true,
        otpVerified: true
      });

    } catch (error) {
      sendError(res, error);
    }
  }
);

// ======================================================
// 12. DRIVER START / COMPLETE
// POST /driver/ride-status
// Started requires customer confirmation and verified OTP.
// ======================================================

app.post(
  "/driver/ride-status",
  strictLimiter,
  requireFirebaseAuth,
  async (req, res) => {
    try {
      onlyKeys(req.body, ["bookingId", "status"]);

      if (!["Started", "Completed"].includes(req.body.status)) {
        fail("Invalid ride status");
      }

      const ref = getBookingRef(req.body.bookingId);
      const privateRef = db.collection("BookingPrivate")
        .doc(req.body.bookingId);

      await db.runTransaction(async transaction => {
        const snap = await transaction.get(ref);
        const driverRef = db.collection("Drivers").doc(req.user.uid);
        const driverSnap = await transaction.get(driverRef);

        if (!snap.exists) fail("Booking नहीं मिली।", 404);
        if (!driverSnap.exists) fail("Driver Profile नहीं मिली।", 403);

        const booking = snap.data();
        const driver = driverSnap.data();

        if (driver.verified !== true || driver.active !== true) {
          fail("Driver Verified और Active नहीं है।", 403);
        }

        if (booking.driverUid !== req.user.uid) {
          fail("यह Booking आपके नाम पर नहीं है।", 403);
        }

        if (req.body.status === "Started") {
          const privateSnap = await transaction.get(privateRef);

          if (!privateSnap.exists) fail("Private Record नहीं मिली।", 404);

          if (
            booking.status !== "Arrived" ||
            booking.customerStartConfirmed !== true ||
            privateSnap.data().rideOtpVerified !== true
          ) {
            fail("Customer Confirmation और OTP Verification जरूरी है।", 409);
          }

          transaction.update(ref, {
            status: "Started",
            rideStartedAt: FieldValue.serverTimestamp()
          });

        } else {
          if (booking.status !== "Started") {
            fail("Ride पहले Started होनी चाहिए।", 409);
          }

          transaction.update(ref, {
            status: "Completed",
            rideCompletedAt: FieldValue.serverTimestamp()
          });
        }
      });

      res.json({
        success: true,
        status: req.body.status
      });

    } catch (error) {
      sendError(res, error);
    }
  }
);

// ======================================================
// 13. DRIVER REPORTS CASH RECEIVED
// POST /driver/payment/cash-confirm
// This does NOT mark payment Paid.
// ======================================================

app.post(
  "/driver/payment/cash-confirm",
  requireFirebaseAuth,
  async (req, res) => {
    try {
      onlyKeys(req.body, ["bookingId"]);

      const ref = getBookingRef(req.body.bookingId);

      await db.runTransaction(async transaction => {
        const snap = await transaction.get(ref);

        if (!snap.exists) fail("Booking नहीं मिली।", 404);

        const booking = snap.data();

        if (booking.driverUid !== req.user.uid) {
          fail("यह Booking आपके नाम पर नहीं है।", 403);
        }

        if (booking.status !== "Completed") {
          fail("Completed Ride के बाद ही Cash Report करें।", 409);
        }

        if (booking.paymentStatus === "Paid") {
          fail("Payment पहले ही Paid है।", 409);
        }

        transaction.update(ref, {
          paymentMethod: "Cash",
          paymentStatus: "CashReported",
          cashReportedAt: FieldValue.serverTimestamp()
        });
      });

      res.json({
        success: true,
        paymentStatus: "CashReported"
      });

    } catch (error) {
      sendError(res, error);
    }
  }
);

// ======================================================
// 14. CUSTOMER REPORTS UPI PAYMENT
// POST /customer/payment/upi-report
// ======================================================

app.post(
  "/customer/payment/upi-report",
  requireFirebaseAuth,
  async (req, res) => {
    try {
      onlyKeys(req.body, ["bookingId", "upiReference"]);

      if (!validText(req.body.upiReference, 100)) {
        fail("Valid UPI Reference आवश्यक है।");
      }

      const ref = getBookingRef(req.body.bookingId);

      await db.runTransaction(async transaction => {
        const snap = await transaction.get(ref);

        if (!snap.exists) fail("Booking नहीं मिली।", 404);

        const booking = snap.data();

        if (booking.customerUid !== req.user.uid) {
          fail("यह Booking आपके नाम पर नहीं है।", 403);
        }

        if (booking.status !== "Completed") {
          fail("Completed Ride के बाद ही UPI Report करें।", 409);
        }

        if (booking.paymentStatus === "Paid") {
          fail("Payment पहले ही Paid है।", 409);
        }

        transaction.update(ref, {
          paymentMethod: "UPI",
          paymentStatus: "UPIReported",
          upiReference: req.body.upiReference.trim(),
          upiReportedAt: FieldValue.serverTimestamp()
        });
      });

      res.json({
        success: true,
        paymentStatus: "UPIReported"
      });

    } catch (error) {
      sendError(res, error);
    }
  }
);

// ======================================================
// 15. ADMIN VERIFY MANUAL CASH / UPI
// ======================================================

async function verifyManualPayment(req, res, method) {
  try {
    onlyKeys(req.body, ["bookingId"]);

    const ref = getBookingRef(req.body.bookingId);

    await db.runTransaction(async transaction => {
      const snap = await transaction.get(ref);

      if (!snap.exists) fail("Booking नहीं मिली।", 404);

      const booking = snap.data();
      const expectedStatus = method === "UPI"
        ? "UPIReported"
        : "CashReported";

      if (booking.status !== "Completed") {
        fail("Ride Completed नहीं है।", 409);
      }

      if (
        booking.paymentMethod !== method ||
        booking.paymentStatus !== expectedStatus
      ) {
        fail("Payment Report उपलब्ध नहीं है।", 409);
      }

      transaction.update(ref, {
        paymentStatus: "Paid",
        paymentVerifiedBy: req.user.uid,
        paymentVerifiedAt: FieldValue.serverTimestamp()
      });
    });

    res.json({
      success: true,
      paymentMethod: method,
      paymentStatus: "Paid"
    });

  } catch (error) {
    sendError(res, error);
  }
}

app.post(
  "/admin/payment/verify-upi",
  requireFirebaseAuth,
  requireAdmin,
  (req, res) => verifyManualPayment(req, res, "UPI")
);

app.post(
  "/admin/payment/verify-cash",
  requireFirebaseAuth,
  requireAdmin,
  (req, res) => verifyManualPayment(req, res, "Cash")
);

// ======================================================
// 16. RAZORPAY CREATE ORDER
// POST /payment/razorpay/order
// ======================================================

app.post(
  "/payment/razorpay/order",
  strictLimiter,
  requireFirebaseAuth,
  async (req, res) => {
    try {
      onlyKeys(req.body, ["bookingId"]);

      const razorpay = makeRazorpay();

      if (!razorpay) {
        return res.status(503).json({
          success: false,
          error: "Razorpay credentials are not configured"
        });
      }

      const ref = getBookingRef(req.body.bookingId);
      const snap = await ref.get();

      if (!snap.exists) fail("Booking नहीं मिली।", 404);

      const booking = snap.data();

      if (booking.customerUid !== req.user.uid) {
        fail("यह Booking आपके नाम पर नहीं है।", 403);
      }

      if (booking.status !== "Completed") {
        fail("Ride Completed होने के बाद Payment करें।", 409);
      }

      if (booking.paymentStatus === "Paid") {
        fail("Payment पहले ही Paid है।", 409);
      }

      const fare = Number(booking.fare);

      if (!Number.isFinite(fare) || fare <= 0) {
        fail("Booking Fare अभी निर्धारित नहीं है।", 409);
      }

      const amount = Math.round(fare * 100);

      const order = await razorpay.orders.create({
        amount,
        currency: "INR",
        receipt: req.body.bookingId
      });

      await ref.update({
        paymentMethod: "Razorpay",
        paymentStatus: "OrderCreated",
        razorpayOrderId: order.id,
        razorpayOrderCreatedAt: FieldValue.serverTimestamp()
      });

      res.json({
        success: true,
        orderId: order.id,
        amount: order.amount,
        currency: order.currency,
        keyId: process.env.RAZORPAY_KEY_ID
      });

    } catch (error) {
      sendError(res, error);
    }
  }
);

// ======================================================
// 17. RAZORPAY VERIFY
// POST /payment/razorpay/verify
// Server fetches payment from Razorpay before marking Paid.
// ======================================================

app.post(
  "/payment/razorpay/verify",
  requireFirebaseAuth,
  async (req, res) => {
    try {
      onlyKeys(req.body, [
        "bookingId",
        "razorpayOrderId",
        "razorpayPaymentId",
        "razorpaySignature"
      ]);

      const razorpay = makeRazorpay();

      if (!razorpay) {
        return res.status(503).json({
          success: false,
          error: "Razorpay credentials are not configured"
        });
      }

      const ref = getBookingRef(req.body.bookingId);
      const snap = await ref.get();

      if (!snap.exists) fail("Booking नहीं मिली।", 404);

      const booking = snap.data();

      if (booking.customerUid !== req.user.uid) {
        fail("यह Booking आपके नाम पर नहीं है।", 403);
      }

      if (booking.status !== "Completed") {
        fail("Ride Completed नहीं है।", 409);
      }

      if (booking.razorpayOrderId !== req.body.razorpayOrderId) {
        fail("Order ID mismatch", 400);
      }

      const payload =
        req.body.razorpayOrderId + "|" + req.body.razorpayPaymentId;

      const expected = crypto
        .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
        .update(payload)
        .digest("hex");

      if (!safeEqualHex(expected, req.body.razorpaySignature)) {
        fail("Invalid Razorpay signature", 401);
      }

      const payment = await razorpay.payments.fetch(
        req.body.razorpayPaymentId
      );

      const expectedAmount = Math.round(Number(booking.fare) * 100);

      if (
        payment.order_id !== req.body.razorpayOrderId ||
        Number(payment.amount) !== expectedAmount ||
        payment.currency !== "INR" ||
        payment.status !== "captured"
      ) {
        fail("Payment capture or amount verification failed", 409);
      }

      await db.runTransaction(async transaction => {
        const current = await transaction.get(ref);

        if (!current.exists) fail("Booking नहीं मिली।", 404);

        const currentBooking = current.data();

        if (
          currentBooking.customerUid !== req.user.uid ||
          currentBooking.razorpayOrderId !== payment.order_id
        ) {
          fail("Booking verification failed", 409);
        }

        transaction.update(ref, {
          paymentMethod: "Razorpay",
          paymentStatus: "Paid",
          razorpayPaymentId: payment.id,
          paymentVerifiedAt: FieldValue.serverTimestamp()
        });
      });

      res.json({
        success: true,
        verified: true,
        paymentStatus: "Paid"
      });

    } catch (error) {
      sendError(res, error);
    }
  }
);

// ======================================================
// 18. ADMIN REGISTER HOTEL PARTNER
// POST /admin/hotels
// Creates HotelPublic document and QR booking URL.
// ======================================================

app.post(
  "/admin/hotels",
  requireFirebaseAuth,
  requireAdmin,
  async (req, res) => {
    try {
      onlyKeys(req.body, ["name", "address", "phone"]);

      if (!validText(req.body.name, 150)) {
        fail("Hotel Name आवश्यक है।");
      }

      if (!validText(req.body.address, 250)) {
        fail("Hotel Address आवश्यक है।");
      }

      if (
        req.body.phone !== undefined &&
        !validText(req.body.phone, 20)
      ) {
        fail("Invalid Hotel Phone");
      }

      const ref = db.collection("HotelPublic").doc();

      const partnerId = "WIMR-" +
        crypto.randomBytes(4).toString("hex").toUpperCase();

      await ref.create({
        partnerId,
        name: req.body.name.trim(),
        address: req.body.address.trim(),
        phone: req.body.phone || "",
        active: true,
        createdAt: FieldValue.serverTimestamp(),
        createdBy: req.user.uid
      });

      const bookingUrl =
        "https://myridebhilwara-45652.web.app/?hotel=" + ref.id;

      res.status(201).json({
        success: true,
        hotelId: ref.id,
        partnerId,
        bookingUrl,
        message: "Hotel Partner Registered"
      });

    } catch (error) {
      sendError(res, error);
    }
  }
);

// ======================================================

// ======================================================
// ADMIN DRIVER VERIFY / ACTIVATE / DEACTIVATE
// POST /admin/driver-status
// ======================================================

app.post(
  "/admin/driver-status",
  requireFirebaseAuth,
  requireAdmin,
  async (req, res) => {
    try {
      onlyKeys(req.body, ["driverUid", "verified", "active"]);

      if (
        !validId(req.body.driverUid) ||
        typeof req.body.verified !== "boolean" ||
        typeof req.body.active !== "boolean"
      ) {
        fail("Invalid Driver UID or status");
      }

      const ref = db.collection("Drivers").doc(req.body.driverUid);
      const snap = await ref.get();

      if (!snap.exists) fail("Driver Profile नहीं मिली।", 404);

      await ref.update({
        verified: req.body.verified,
        active: req.body.active,
        updatedAt: FieldValue.serverTimestamp()
      });

      res.json({
        success: true,
        verified: req.body.verified,
        active: req.body.active
      });

    } catch (error) {
      sendError(res, error);
    }
  }
);

// 19. ADMIN ACTIVATE / DEACTIVATE HOTEL
// POST /admin/hotels/status
// ======================================================

app.post(
  "/admin/hotels/status",
  requireFirebaseAuth,
  requireAdmin,
  async (req, res) => {
    try {
      onlyKeys(req.body, ["hotelId", "active"]);

      if (!validId(req.body.hotelId) ||
          typeof req.body.active !== "boolean") {
        fail("Hotel ID and active boolean required");
      }

      const ref = db.collection("HotelPublic").doc(req.body.hotelId);
      const snap = await ref.get();

      if (!snap.exists) fail("Hotel नहीं मिला।", 404);

      await ref.update({
        active: req.body.active,
        updatedAt: FieldValue.serverTimestamp()
      });

      res.json({
        success: true,
        active: req.body.active
      });

    } catch (error) {
      sendError(res, error);
    }
  }
);

// ======================================================
// 20. NOT FOUND + ERROR HANDLER
// ======================================================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "API endpoint not found"
  });
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);

  if (error.type === "entity.too.large") {
    return res.status(413).json({
      success: false,
      error: "Request body is too large"
    });
  }

  if (error instanceof SyntaxError && error.status === 400) {
    return res.status(400).json({
      success: false,
      error: "Invalid JSON request"
    });
  }

  console.error("Backend error:", error.message);

  return res.status(500).json({
    success: false,
    error: "Internal server error"
  });
});

// ======================================================
// START SERVER
// ======================================================

app.listen(PORT, "0.0.0.0", () => {
  console.log("========================================");
  console.log(" WHERE IS MY RIDE BACKEND");
  console.log(" Project:", PROJECT_ID);
  console.log(" Port:", PORT);
  console.log("========================================");
});
