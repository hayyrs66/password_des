process.loadEnvFile();

import type { APIRoute } from "astro";
import crypto from "crypto";

const rsaPrivateKey = process.env.RSA_PRIVATE_KEY!.replace(/\\n/g, '\n');;
console.log('RSA Private Key:', rsaPrivateKey);

function deriveDESKeyFromPassword(password: string): Buffer {
  return crypto.pbkdf2Sync(password, "salt", 1000, 8, "sha256");
}

function decryptWithDES(encryptedData: string, password: string) {
  const desKey = deriveDESKeyFromPassword(password);
  const decipher = crypto.createDecipheriv("des-ecb", desKey, null);
  return Buffer.concat([
    decipher.update(Buffer.from(encryptedData, "base64")),
    decipher.final(),
  ]).toString("utf8");
}

function decryptPasswordWithRSA(encryptedPassword: string) {
  return crypto
    .privateDecrypt(
      {
        key: rsaPrivateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(encryptedPassword, "base64")
    )
    .toString("utf8");
}


export const POST: APIRoute = async ({ request }) => {
  const formData = await request.formData();
  const masterPassword = formData.get("master_password") as string;
  const file = formData.get("file") as File;

  if (!masterPassword || !file) {
    return new Response(JSON.stringify({ error: "All fields are required" }), { status: 400 });
  }

  const encryptedJson = await file.text();

  let decryptedJson;
  try {
    decryptedJson = decryptWithDES(encryptedJson, masterPassword);
    console.log("File decrypted with DES.");
  } catch (error) {
    console.error("Error decrypting JSON file with DES:", error);
    return new Response(JSON.stringify({ error: "Decryption failed" }), { status: 500 });
  }

  const data = JSON.parse(decryptedJson);

  data.entries = data.entries.map((entry) => {
    console.log("Encrypted password:", entry.password); // Log the encrypted password
    
    const decryptedPassword = decryptPasswordWithRSA(entry.password);
    console.log("Decrypted password:", decryptedPassword); // Log the decrypted password (optional)
  
    return {
      ...entry,
      password: decryptedPassword,
    };
  });
  


  console.log(data)

  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
};
