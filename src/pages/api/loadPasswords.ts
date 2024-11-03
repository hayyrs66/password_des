// Endpoint: loadPasswords
process.loadEnvFile();
import type { APIRoute } from "astro";
import crypto from "crypto";
import forge from "node-forge";

const rsaPrivateKey = process.env.RSA_PRIVATE_KEY!.replace(/\\n/g, "\n");
const privateKey = forge.pki.privateKeyFromPem(rsaPrivateKey);

function formatDESKey(password) {
  return Buffer.byteLength(password, 'utf8') === 8
    ? Buffer.from(password, "utf8")
    : Buffer.from(password.padEnd(8, ' '), "utf8");
}

// DES Decryption with ECB mode and PKCS7 padding
function decryptWithDES(encryptedData, password) {
  const desKey = formatDESKey(password);
  const decipher = crypto.createDecipheriv("des-ecb", desKey, null);
  decipher.setAutoPadding(true);
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encryptedData, "base64")),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

// RSA Decryption with PKCS1 v1.5 padding
function decryptPasswordWithRSA(encryptedPassword) {
  const decrypted = privateKey.decrypt(Buffer.from(encryptedPassword, 'base64').toString('binary'), 'RSAES-PKCS1-V1_5');
  return decrypted;
}

export const POST: APIRoute = async ({ request }) => {
  const formData = await request.formData();
  const masterPassword = formData.get("master_password") as string;
  const file = formData.get("file") as File;

  if (!masterPassword || !file) {
    return new Response(JSON.stringify({ error: "All fields are required" }), { status: 400 });
  }

  const encryptedArrayBuffer = await file.arrayBuffer();
  const encryptedBuffer = Buffer.from(encryptedArrayBuffer);

  let decryptedJson;
  try {
    // Decrypt using DES-ECB and PKCS7
    decryptedJson = decryptWithDES(encryptedBuffer, masterPassword);
    console.log("File decrypted with DES.");
  } catch (error) {
    console.error("Error decrypting JSON file with DES:", error);
    return new Response(JSON.stringify({ error: "Decryption failed" }), { status: 500 });
  }

  const data = JSON.parse(decryptedJson);

  // Decrypt each password with RSA
  data.entries = data.entries.map((entry) => ({
    ...entry,
    password: decryptPasswordWithRSA(entry.password),
  }));

  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
};

