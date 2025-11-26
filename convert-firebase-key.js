import fs from "fs";

// Read your downloaded serviceAccount.json
const raw = fs.readFileSync("./serviceAccount.json", "utf8");
const json = JSON.parse(raw);

// Escape newlines in the private key
json.private_key = json.private_key.replace(/\n/g, "\\n");

// Convert to one-line JSON string
const envValue = JSON.stringify(json);

// Write to .env file
fs.writeFileSync(".env", `FIREBASE_CONFIG='${envValue}'\n`);

console.log("✅ .env file updated with FIREBASE_CONFIG");
