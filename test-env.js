import dotenv from "dotenv";
dotenv.config();

console.log("Firebase key:", process.env.FIREBASE_SERVICE_ACCOUNT_KEY?.slice(0, 50));
console.log("PayPal client:", process.env.PAYPAL_CLIENT_ID?.slice(0, 20));
import dotenv from "dotenv";
dotenv.config();

console.log("Keys loaded:", Object.keys(process.env));
