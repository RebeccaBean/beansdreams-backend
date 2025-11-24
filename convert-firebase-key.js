import fs from "fs";

// Read your service account JSON file
const serviceAccount = JSON.parse(fs.readFileSync("serviceAccount.json", "utf8"));

// Escape newlines in the private key
serviceAccount.private_key = serviceAccount.private_key.replace(/\n/g, "\\n");

// Print the .env line
console.log("FIREBASE_SERVICE_ACCOUNT_KEY=" + JSON.stringify(serviceAccount));
