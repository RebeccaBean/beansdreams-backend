// firebase.js
import dotenv from "dotenv";
import admin from "firebase-admin";

dotenv.config();

// Parse service account JSON from .env
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);

// Fix private key formatting
serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, "\n");

// Initialize Firebase Admin once
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

// Export Firestore and Admin
const db = admin.firestore();
export { admin, db };
