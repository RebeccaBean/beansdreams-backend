/* ---------------------------
   Imports & Setup
--------------------------- */
import express from "express";
import dotenv from "dotenv";
import fetch from "node-fetch";
import cors from "cors";
import bodyParser from "body-parser";
import path from "path";
import fs from "fs";
import admin from "firebase-admin";
import paypal from "paypal-rest-sdk";
import { fileURLToPath } from "url";
import { db } from "./firebase.js";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;

/* ---------------------------
   Middleware & Static Files
--------------------------- */
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static("public")); // serve success/cancel pages and other assets

/* ---------------------------
   Env Checks
--------------------------- */
if (!process.env.FIREBASE_SERVICE_ACCOUNT_KEY) {
  console.error("ERROR: FIREBASE_SERVICE_ACCOUNT_KEY missing in .env");
  process.exit(1);
}
if (!process.env.PAYPAL_CLIENT_ID || !process.env.PAYPAL_SECRET) {
  console.warn("Warning: PayPal client id/secret not found in .env (set for sandbox/live).");
}

/* ---------------------------
   Firebase Admin Init
--------------------------- */
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL || undefined,
  });
}
const firestore = admin.firestore();

/* ---------------------------
   PayPal Setup
--------------------------- */
const PAYPAL_API_BASE =
  process.env.PAYPAL_MODE === "live"
    ? "https://api-m.paypal.com"
    : "https://api-m.sandbox.paypal.com";

const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || "";
const PAYPAL_SECRET = process.env.PAYPAL_SECRET || "";

paypal.configure({
  mode: process.env.PAYPAL_MODE || "sandbox",
  client_id: PAYPAL_CLIENT_ID,
  client_secret: PAYPAL_SECRET,
});

async function getPayPalAccessToken() {
  const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_SECRET}`).toString("base64");
  const resp = await fetch(`${PAYPAL_API_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials",
  });
  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error(`PayPal token error: ${resp.status} ${txt}`);
  }
  const data = await resp.json();
  return data.access_token;
}

/* ---------------------------
   External APIs
--------------------------- */
const PRINTIFY_API_KEY = process.env.PRINTIFY_API_KEY || "";
const ZAPIER_WEBHOOK_URL = process.env.ZAPIER_WEBHOOK_URL || "";
const FRONTEND_URL = process.env.FRONTEND_URL || "https://beansdreams.org";

/* ---------------------------
   Bundles & Subscription Plans
--------------------------- */
const BUNDLES = {
  "paypal-melody-makers": { credits: 12, type: { Vocal: 6, Guitar: 6 }, name: "Melody Makers" },
  "paypal-dance-music": { credits: 8, type: { Dance: 4, Any: 4 }, name: "Dance & Music" },
  "paypal-dreamers-dozen": { credits: 12, type: { Any: 12 }, name: "Dreamers Dozen" },
  "paypal-treble-treat": { credits: 3, type: { Vocal: 1, Guitar: 1, Dance: 1 }, name: "Treble Treat" },
  "paypal-encore-elite": { credits: 8, type: { Any: 8 }, name: "Encore Elite" },
  "paypal-serenity-series": { credits: 6, type: { Healing: 6 }, name: "Serenity Series" },
  "paypal-harmony-healers": { credits: 6, type: { Healing: 4, Any: 2 }, name: "Harmony Healers" },
  "paypal-creative-express": { credits: 6, type: { Dance: 3, Vocal: 3 }, name: "Creative Express" },
  "paypal-coach-4session": { credits: 4, type: { Coaching: 4 }, name: "Coach 4-session Pack" },
  "paypal-coach-monthly": { credits: 8, type: { Coaching: 8 }, name: "Monthly Coaching Pack" },
  "paypal-coach-deep": { credits: 10, type: { Coaching: 10 }, name: "Deep Coaching" },
  "paypal-coach-dreamseries": { credits: 6, type: { Coaching: 6 }, name: "Coach Dream Series" },
  "paypal-coach-mindful-momentum": { credits: 5, type: { Coaching: 5 }, name: "Mindful Momentum Coaching" }
};

const SUBSCRIPTION_PLANS = {
  classPass: { planId: process.env.PAYPAL_PLAN_CLASS || "P-CLASSID", credits: 4, type: { Any: 4 }, name: "Monthly Class Pass" },
  coachingPass: { planId: process.env.PAYPAL_PLAN_COACH || "P-COACHID", credits: 4, type: { Coaching: 4 }, name: "Monthly Coaching Pass" },
};

/* ---------------------------
   Helpers: credits, pending orders, zapier
--------------------------- */
async function applyCreditsByUid(uid, credits, typeObj = {}, meta = {}) {
  if (!uid) throw new Error("applyCreditsByUid: missing uid");
  const docRef = firestore.collection("students").doc(uid);
  const snap = await docRef.get();
  const current = snap.exists ? snap.data() : {};
  const existing = current.remainingCredits || { total: 0, byType: {} };

  const mergedByType = { ...(existing.byType || {}) };
  for (const k of Object.keys(typeObj || {})) {
    mergedByType[k] = (mergedByType[k] || 0) + (typeObj[k] || 0);
  }

  const updatedRemaining = {
    total: (existing.total || 0) + credits,
    byType: mergedByType,
  };

  const entry = {
    creditsAdded: credits,
    type: typeObj,
    meta,
    date: new Date().toISOString(),
  };

  await docRef.set(
    {
      remainingCredits: updatedRemaining,
      paymentHistory: admin.firestore.FieldValue.arrayUnion(entry),
      lastUpdated: new Date().toISOString(),
    },
    { merge: true }
  );

  console.log(`Applied ${credits} credits to uid=${uid}`);
}

async function savePendingOrderByEmail(email, orderRecord) {
  if (!email) throw new Error("savePendingOrderByEmail: missing email");
  const docId = encodeURIComponent(email);
  const docRef = firestore.collection("pendingOrders").doc(docId);
  await docRef.set(
    {
      email,
      orders: admin.firestore.FieldValue.arrayUnion(orderRecord),
      lastUpdated: new Date().toISOString(),
    },
    { merge: true }
  );
  console.log(`Saved pending order for ${email}`);
}

async function mergePendingOrdersForUid(uid, email) {
  if (!uid || !email) throw new Error("mergePendingOrdersForUid: missing uid or email");
  const docId = encodeURIComponent(email);
  const pendingRef = firestore.collection("pendingOrders").doc(docId);
  const pendingSnap = await pendingRef.get();
  if (!pendingSnap.exists) {
    console.log("No pending orders for", email);
    return { merged: 0 };
  }
  const data = pendingSnap.data();
  const orders = data.orders || [];
  let mergedCount = 0;

  for (const o of orders) {
    const cart = o.cart || [];
    for (const item of cart) {
      if (item.bundleKey && BUNDLES[item.bundleKey]) {
        const bundle = BUNDLES[item.bundleKey];
        await applyCreditsByUid(uid, bundle.credits, bundle.type, { source: "pending_merge", orderId: o.orderId || null });
      }
      if (item.type === "digital" && item.productId) {
        await firestore.collection("students").doc(uid).set(
          { downloads: admin.firestore.FieldValue.arrayUnion(item.productId) },
          { merge: true }
        );
      }
    }
    await firestore.collection("orders").add({ ...o, uid, mergedFromPending: true, mergedAt: new Date().toISOString() });
    mergedCount++;
  }

  await pendingRef.delete();
  console.log(`Merged ${mergedCount} pending orders for ${email} -> uid ${uid}`);
  return { merged: mergedCount };
}

async function notifyZapier(eventName, payload = {}) {
  if (!ZAPIER_WEBHOOK_URL) return;
  try {
    await fetch(ZAPIER_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ event: eventName, ...payload }),
    });
  } catch (err) {
    console.error("Zapier notify failed:", err);
  }
}

/* ---------------------------
   Middleware: verify Firebase ID token
--------------------------- */
async function verifyFirebaseIdToken(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const match = authHeader.match(/^Bearer (.+)$/);
  if (!match) {
    return res.status(401).json({ error: "Missing ID token in Authorization header (Bearer <idToken>)" });
  }
  const idToken = match[1];
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = decoded; // contains uid, email, etc.
    next();
  } catch (err) {
    console.error("verifyFirebaseIdToken failed:", err);
    return res.status(401).json({ error: "Invalid or expired ID token" });
  }
}

/* ---------------------------
   ROUTES
--------------------------- */

// === SINGLE CLASS PURCHASE (unprotected, logs payment and +1 credit) ===
app.post("/api/class/single/purchase", async (req, res) => {
  try {
    const { userId, className, classType, amount, payer, orderId } = req.body;

    const userRef = firestore.collection("students").doc(userId);
    const userDoc = await userRef.get();
    const existingCredits = userDoc.exists ? userDoc.data().credits || 0 : 0;

    await userRef.set({
      credits: existingCredits + 1, // legacy simple credits counter
      lastUpdated: new Date().toISOString(),
      lastPurchase: className,
      paymentHistory: admin.firestore.FieldValue.arrayUnion({
        orderId,
        className,
        classType,
        amount,
        payer,
        date: new Date().toISOString()
      })
    }, { merge: true });

    if (process.env.ZAPIER_WEBHOOK_URL) {
      fetch(process.env.ZAPIER_WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: "single_class_purchase",
          userId,
          className,
          classType,
          amount,
          payer,
          orderId
        })
      }).catch(err => console.error("Zapier forward failed:", err));
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Single class purchase error:", err);
    res.status(500).json({ error: "Failed to log single class purchase" });
  }
});

/**
 * POST /create-subscription
 * Body: { type: "classPass"|"coachingPass" }
 * Protected
 */
app.post("/create-subscription", verifyFirebaseIdToken, async (req, res) => {
  try {
    const { type } = req.body;
    const uid = req.user.uid;
    const email = req.user.email;

    if (!type || !SUBSCRIPTION_PLANS[type]) return res.status(400).json({ error: "Missing or invalid subscription type" });
    const plan = SUBSCRIPTION_PLANS[type];

    const token = await getPayPalAccessToken();
    const resp = await fetch(`${PAYPAL_API_BASE}/v1/billing/subscriptions`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        plan_id: plan.planId,
        custom_id: uid, // attach uid so webhooks can map quickly
        application_context: {
          brand_name: "Bean's Dreams",
          user_action: "SUBSCRIBE_NOW",
          return_url: `${FRONTEND_URL}/success.html?uid=${encodeURIComponent(uid)}&type=${type}`,
          cancel_url: `${FRONTEND_URL}/cancel.html`,
        },
      }),
    });
    const data = await resp.json();

    await firestore.collection("students").doc(uid).set(
      {
        subscriptions: admin.firestore.FieldValue.arrayUnion({ planType: type, createdAt: new Date().toISOString(), status: "created", subscriptionId: data?.id || null }),
        email,
      },
      { merge: true }
    );

    notifyZapier("subscription_created", { uid, email, type, paypal: Boolean(data.id || data.links) });

    res.json(data);
  } catch (err) {
    console.error("/create-subscription error", err);
    res.status(500).json({ error: "Failed to create subscription" });
  }
});

/**
 * POST /capture-order
 * Protected
 * Body: { order, cart }
 * Expected: frontend calls this after PayPal onApprove and sends PayPal capture result + cart
 */
app.post("/capture-order", verifyFirebaseIdToken, async (req, res) => {
  try {
    const { order, cart } = req.body;
    const uid = req.user.uid;
    const email = req.user.email;

    if (!order || !cart) return res.status(400).json({ error: "Missing order or cart" });

    const orderRecord = {
      uid,
      email,
      cart,
      paypalOrder: order,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      status: "completed",
    };
    const orderDoc = await firestore.collection("orders").add(orderRecord);

    const downloadIds = [];
    for (const item of cart) {
      if (item.bundleKey && BUNDLES[item.bundleKey]) {
        const bundle = BUNDLES[item.bundleKey];
        await applyCreditsByUid(uid, bundle.credits, bundle.type, { source: "bundle_purchase", orderId: orderDoc.id });
      }
      if (item.type === "digital" && item.productId) {
        downloadIds.push(item.productId);
      }
      if (item.type === "merch" && item.printifyProductId && PRINTIFY_API_KEY) {
        try {
          const printifyOrder = {
            external_id: `order-${orderDoc.id}`,
            shop_id: item.printifyShopId || process.env.PRINTIFY_SHOP_ID,
            line_items: [
              { product_id: item.printifyProductId, variant_id: item.printifyVariantId, quantity: item.quantity || 1 },
            ],
            customer: {
              email,
              first_name: order?.payer?.name?.given_name || "",
              last_name: order?.payer?.name?.surname || "",
            },
            send_shipping_notification: false,
          };
          const pfResp = await fetch(`https://api.printify.com/v1/shops/${printifyOrder.shop_id}/orders.json`, {
            method: "POST",
            headers: { Authorization: `Bearer ${PRINTIFY_API_KEY}`, "Content-Type": "application/json" },
            body: JSON.stringify(printifyOrder),
          });
          const pfData = await pfResp.json();
          await firestore.collection("orders").doc(orderDoc.id).set({ printify: pfData }, { merge: true });
        } catch (err) {
          console.error("Printify order creation error", err);
        }
      }
    }

    if (downloadIds.length) {
      await firestore.collection("students").doc(uid).set({ downloads: admin.firestore.FieldValue.arrayUnion(...downloadIds) }, { merge: true });
    }

    notifyZapier("order_completed", { uid, email, orderId: orderDoc.id, cart });

    res.json({ success: true, orderId: orderDoc.id });
  } catch (err) {
    console.error("/capture-order error", err);
    res.status(500).json({ error: "Failed to capture order" });
  }
});

/**
 * POST /buy-single-class
 * Protected
 * Body: { classType }
 * Creates a pending single-class entry and returns Calendly redirect URL
 */
app.post("/buy-single-class", verifyFirebaseIdToken, async (req, res) => {
  try {
    const { classType } = req.body;
    const uid = req.user.uid;
    const email = req.user.email;

    if (!classType) return res.status(400).json({ error: "Missing classType" });

    const pending = {
      uid,
      email,
      classType,
      status: "redirected-to-calendly",
      createdAt: new Date().toISOString(),
    };
    const docRef = await firestore.collection("singleClassPurchases").add(pending);

    const calendlyMap = {
      Guitar: "https://calendly.com/nickrebbean-epkm/guitar-30",
      Vocal: "https://calendly.com/nickrebbean-epkm/vocal-30",
      Dance: "https://calendly.com/nickrebbean-epkm/dance-30",
      Coaching: "https://calendly.com/nickrebbean-epkm/coaching-60",
    };
    const redirect = calendlyMap[classType] || "https://calendly.com/nickrebbean-epkm";

    notifyZapier("single_class_started", { uid, email, classType, pendingId: docRef.id });

    res.json({ ok: true, redirect, pendingId: docRef.id });
  } catch (err) {
    console.error("/buy-single-class error", err);
    res.status(500).json({ error: "Failed to create single class purchase" });
  }
});

/**
 * POST /merge-pending-orders
 * Protected
 * Body: {}
 * Use after new user signup to attach pending orders by email to UID
 */
app.post("/merge-pending-orders", verifyFirebaseIdToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    const email = req.user.email;
    if (!uid || !email) return res.status(400).json({ error: "Missing uid/email" });

    const result = await mergePendingOrdersForUid(uid, email);
    res.json({ success: true, merged: result.merged });
  } catch (err) {
    console.error("/merge-pending-orders error", err);
    res.status(500).json({ error: "Failed to merge pending orders" });
  }
});

/**
 * POST /create-pending-order
 * Unprotected (internal usage by webhook or capture without uid)
 * Body: { email, cart, paypalOrder, orderId? }
 */
app.post("/create-pending-order", async (req, res) => {
  try {
    const { email, cart, paypalOrder } = req.body;
    if (!email || !cart) return res.status(400).json({ error: "Missing email or cart" });

    const orderRecord = {
      email,
      cart,
      paypalOrder: paypalOrder || null,
      createdAt: new Date().toISOString(),
      orderId: `pending-${Date.now()}`,
    };
    await savePendingOrderByEmail(email, orderRecord);
    notifyZapier("pending_order_created", { email, orderId: orderRecord.orderId });
    res.json({ success: true, orderId: orderRecord.orderId });
  } catch (err) {
    console.error("/create-pending-order error", err);
    res.status(500).json({ error: "Failed to create pending order" });
  }
});

/**
 * PayPal webhook endpoint (raw body required by PayPal)
 * Configure this URL in PayPal Developer console
 */
app.post("/paypal-webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    const body = JSON.parse(req.body.toString("utf8"));

    const transmissionId = req.headers["paypal-transmission-id"];
    const transmissionTime = req.headers["paypal-transmission-time"];
    const certUrl = req.headers["paypal-cert-url"];
    const authAlgo = req.headers["paypal-auth-algo"];
    const transmissionSig = req.headers["paypal-transmission-sig"];
    const webhookId = process.env.PAYPAL_WEBHOOK_ID;

    const accessToken = await getPayPalAccessToken();
    const verifyResp = await fetch(`${PAYPAL_API_BASE}/v1/notifications/verify-webhook-signature`, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        auth_algo: authAlgo,
        cert_url: certUrl,
        transmission_id: transmissionId,
        transmission_sig: transmissionSig,
        transmission_time: transmissionTime,
        webhook_id: webhookId,
        webhook_event: body,
      }),
    });
    const verifyData = await verifyResp.json();
    if (verifyData.verification_status !== "SUCCESS") {
      console.warn("PayPal webhook signature invalid", verifyData);
      return res.status(400).send("Invalid webhook signature");
    }

    const eventType = body.event_type;
    console.log("PayPal webhook event:", eventType);

    let email = body.resource?.payer?.email_address || body.resource?.subscriber?.email_address || null;
    let uid = null;
    if (email) {
      const userSnap = await firestore.collection("students").where("email", "==", email).limit(1).get();
      if (!userSnap.empty) uid = userSnap.docs[0].id;
    }

    if (eventType === "PAYMENT.CAPTURE.COMPLETED") {
      const resource = body.resource;
      const relatedOrderId = resource.supplementary_data?.related_ids?.order_id || resource.invoice_id || null;

      if (uid) {
        await applyCreditsByUid(uid, 0, {}, { source: "paypal_capture", note: "capture event received", relatedOrderId });
      } else if (email) {
        await savePendingOrderByEmail(email, { cart: [], paypalOrder: resource, createdAt: new Date().toISOString(), orderId: relatedOrderId || `pending-${Date.now()}` });
        notifyZapier("pending_order_created_via_webhook", { email });
      }
    }

    if (eventType === "BILLING.SUBSCRIPTION.PAYMENT.SUCCEEDED" || eventType === "BILLING.SUBSCRIPTION.CHARGED_SUCCESSFULLY") {
      const resource = body.resource;
      email = email || resource?.subscriber?.email_address || null;
      const subscriptionId = resource?.id || resource?.billing_agreement_id || null;

      if (!uid && subscriptionId) {
        const subsSnap = await firestore
          .collection("students")
          .where("subscriptions", "array-contains", { subscriptionId })
          .limit(1)
          .get()
          .catch(() => null);
        if (subsSnap && !subsSnap.empty) {
          uid = subsSnap.docs[0].id;
        }
      }

      if (uid) {
        // Resolve plan type from student's subscriptions or default
        const studentDoc = await firestore.collection("students").doc(uid).get();
        const subs = studentDoc.exists ? (studentDoc.data().subscriptions || []) : [];
        const matched = subs.find(s => s.subscriptionId === subscriptionId);
        const planType = matched?.planType || "classPass";
        const plan = SUBSCRIPTION_PLANS[planType] || { credits: 4, type: { Any: 4 } };

        await applyCreditsByUid(uid, plan.credits, plan.type, { source: "paypal_subscription_renewal", subscriptionId });
        notifyZapier("subscription_payment_succeeded", { uid, subscriptionId, planType });
      } else if (email) {
        await savePendingOrderByEmail(email, { type: "subscription_renewal", resource, createdAt: new Date().toISOString(), orderId: `pending-sub-${Date.now()}` });
        notifyZapier("pending_subscription_renewal", { email });
      }
    }

    await firestore.collection("paypalWebhooks").add({ body, receivedAt: admin.firestore.FieldValue.serverTimestamp() });
    res.status(200).send("OK");
  } catch (err) {
    console.error("paypal-webhook handler error:", err);
    res.status(500).send("Internal Server Error");
  }
});

/**
 * Printify webhook
 * Save the event and optionally update order status
 */
app.post("/printify-webhook", async (req, res) => {
  try {
    const event = req.body;
    await firestore.collection("printifyEvents").add({ event, receivedAt: admin.firestore.FieldValue.serverTimestamp() });
    notifyZapier("printify_event", { event });
    res.status(200).send("OK");
  } catch (err) {
    console.error("/printify-webhook error", err);
    res.status(500).send("Error");
  }
});

/**
 * Calendly webhook endpoint
 * Configure this URL in Calendly's integrations panel
 */
app.post("/calendly-webhook", async (req, res) => {
  try {
    const event = req.body;
    const email = event?.payload?.invitee?.email;
    const classTypeName = event?.payload?.event_type?.name || "Unknown";

    if (!email) {
      console.warn("Calendly webhook missing email", event);
      return res.status(400).send("Missing email");
    }

    const snap = await firestore.collection("students").where("email", "==", email).limit(1).get();
    if (snap.empty) {
      await savePendingOrderByEmail(email, {
        type: "calendly_booking",
        event,
        createdAt: new Date().toISOString(),
      });
      notifyZapier("pending_calendly_booking", { email, classTypeName });
      await firestore.collection("calendlyEvents").add({ event, email, receivedAt: admin.firestore.FieldValue.serverTimestamp() });
      return res.status(200).send("Pending booking saved");
    }

    const uid = snap.docs[0].id;

    await applyCreditsByUid(uid, 1, { [classTypeName]: 1 }, { source: "calendly_booking", eventId: event?.payload?.event?.uuid });

    const purchasesSnap = await firestore.collection("singleClassPurchases")
      .where("email", "==", email)
      .orderBy("createdAt", "desc")
      .limit(1)
      .get();

    if (!purchasesSnap.empty) {
      const purchaseDoc = purchasesSnap.docs[0].ref;
      await purchaseDoc.set({ status: "scheduled", scheduledAt: new Date().toISOString() }, { merge: true });
    }

    notifyZapier("calendly_booking_confirmed", { uid, email, classTypeName });

    await firestore.collection("calendlyEvents").add({
      event,
      uid,
      email,
      receivedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.status(200).send("OK");
  } catch (err) {
    console.error("/calendly-webhook error", err);
    res.status(500).send("Error");
  }
});

/* ---------------------------
   Secure Downloads
--------------------------- */
app.get("/downloads/:productId", verifyFirebaseIdToken, async (req, res) => {
  try {
    const { productId } = req.params;
    const uid = req.user.uid;
    const doc = await firestore.collection("students").doc(uid).get();
    if (!doc.exists) return res.status(403).json({ error: "Unauthorized" });

    const downloads = doc.data().downloads || [];
    if (!downloads.includes(productId)) return res.status(403).json({ error: "Unauthorized - not purchased" });

    const filePath = path.join(__dirname, "private", "downloads", `${productId}.zip`);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: "File not found" });
    res.download(filePath);
  } catch (err) {
    console.error("/downloads error", err);
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------------------------
   Portal APIs
--------------------------- */
app.get("/api/users/:uid/credits", verifyFirebaseIdToken, async (req, res) => {
  try {
    const { uid } = req.params;
    if (req.user.uid !== uid) return res.status(403).json({ error: "Forbidden" });

    const doc = await firestore.collection("students").doc(uid).get();
    const data = doc.exists ? doc.data() : {};
    res.json({
      remainingCredits: data.remainingCredits || { total: 0, byType: {} },
      paymentHistory: data.paymentHistory || [],
      subscriptions: data.subscriptions || [],
      downloads: data.downloads || [],
    });
  } catch (err) {
    console.error("/api/users/:uid/credits error", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/users/:uid/orders", verifyFirebaseIdToken, async (req, res) => {
  try {
    const { uid } = req.params;
    if (req.user.uid !== uid) return res.status(403).json({ error: "Forbidden" });

    const ordersSnap = await firestore.collection("orders").where("uid", "==", uid).orderBy("createdAt", "desc").limit(50).get();
    const orders = ordersSnap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json({ orders });
  } catch (err) {
    console.error("/api/users/:uid/orders error", err);
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------------------------
   Admin utility (testing)
--------------------------- */
app.post("/admin/lookup-email", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Missing email" });
    const snap = await firestore.collection("students").where("email", "==", email).limit(1).get();
    if (snap.empty) return res.json({ found: false });
    const doc = snap.docs[0];
    res.json({ found: true, uid: doc.id, data: doc.data() });
  } catch (err) {
    console.error("/admin/lookup-email error", err);
    res.status(500).json({ error: "Server error" });
  }
});
/**
 * POST /create-order
 * Unprotected
 * Creates a PayPal order and returns its ID
 */
app.post("/create-order", async (req, res) => {
  try {
    const accessToken = await getPayPalAccessToken();
    const resp = await fetch(`${PAYPAL_API_BASE}/v2/checkout/orders`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        intent: "CAPTURE",
        purchase_units: [
          {
            amount: { currency_code: "USD", value: "10.00" }, // test amount
          },
        ],
      }),
    });
    const data = await resp.json();
    res.json(data); // return JSON with order id
  } catch (err) {
    console.error("/create-order error:", err);
    res.status(500).json({ error: "Failed to create order" });
  }
});

/* ---------------------------
   Start server
--------------------------- */
app.listen(PORT, () => {
  console.log(`Bean's Dreams backend running on port ${PORT}`);
});
