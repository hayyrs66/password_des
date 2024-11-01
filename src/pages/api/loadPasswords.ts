import type { APIRoute } from "astro";
import fs from "fs/promises";
import path from "path";
import crypto from "crypto";

const jsonFilePath = path.join(process.cwd(), "passwords.json");
const rsaPrivateKey = process.env.RSA_PRIVATE_KEY!;

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
  return crypto.privateDecrypt(
    {
      key: rsaPrivateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(encryptedPassword, "base64")
  ).toString("utf8");
}


export const POST: APIRoute = async ({ request }) => {
  try {
    const { master_password } = await request.json();

    if (!master_password) {
      return new Response(JSON.stringify({ error: "Master password is required" }), { status: 400 });
    }

    let encryptedJson;
    try {
      encryptedJson = await fs.readFile(jsonFilePath, "utf8");
    } catch (error) {
      console.error("Error reading JSON file:", error);
      return new Response(JSON.stringify({ error: "File not found or inaccessible" }), { status: 404 });
    }

    let decryptedJson;
    try {
      decryptedJson = decryptWithDES(encryptedJson, master_password);
      console.log("File decrypted with DES.");
    } catch (error) {
      console.error("Error decrypting JSON file with DES:", error);
      return new Response(JSON.stringify({ error: "Decryption failed" }), { status: 500 });
    }

    const data = JSON.parse(decryptedJson);

    // Desencriptar cada contraseña con la clave privada RSA
    data.entries = data.entries.map((entry) => ({
      ...entry,
      password: decryptPasswordWithRSA(entry.password),
    }));

    return new Response(JSON.stringify(data), { status: 200, headers: { "Content-Type": "application/json" } });
  } catch (error) {
    console.error("Unexpected error:", error);
    return new Response(JSON.stringify({ error: "Internal server error" }), { status: 500 });
  }
};
