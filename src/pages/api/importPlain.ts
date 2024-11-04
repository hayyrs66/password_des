// importPlain.ts

process.loadEnvFile();

import type { APIRoute } from "astro";
import crypto from "crypto";
import forge from "node-forge";

const rsaPublicKey = process.env.RSA_PUBLIC_KEY!;
const publicKey = forge.pki.publicKeyFromPem(rsaPublicKey);

function formatDESKey(password: string) {
  return Buffer.byteLength(password, "utf8") === 8
    ? Buffer.from(password, "utf8")
    : Buffer.from(password.padEnd(8, " "), "utf8");
}

function encryptWithDES(data: string, password: string) {
  const desKey = formatDESKey(password);
  const cipher = crypto.createCipheriv("des-ecb", desKey, null);
  cipher.setAutoPadding(true);
  return Buffer.concat([cipher.update(Buffer.from(data, "utf8")), cipher.final()]);
}

function encryptPasswordWithRSA(data: string) {
  const buffer = Buffer.from(data, "utf8");
  const encrypted = publicKey.encrypt(buffer.toString("binary"), "RSAES-PKCS1-V1_5");
  return Buffer.from(encrypted, "binary").toString("base64");
}

export const POST: APIRoute = async ({ request }) => {
  try {
    const formData = await request.formData();
    const masterPassword = formData.get("master_password") as string;
    const file = formData.get("file") as File;

    if (!masterPassword || !file) {
      return new Response(
        JSON.stringify({ message: "Master password and file are required" }),
        { status: 400 }
      );
    }

    // Read and parse the content of the plain JSON file
    let jsonData;
    try {
      const plainContent = await file.text();
      jsonData = JSON.parse(plainContent);
    } catch (error) {
      console.error("Error parsing JSON file:", error);
      return new Response(
        JSON.stringify({ message: "Failed to parse JSON file" }),
        { status: 400 }
      );
    }

    // Validate that entries is an array
    if (!jsonData || !Array.isArray(jsonData.entries)) {
      return new Response(
        JSON.stringify({ message: "Invalid JSON format: 'entries' array is missing or not an array" }),
        { status: 400 }
      );
    }

    // Encrypt each password individually with RSA
    const decryptedEntries = jsonData.entries.map((entry: any) => ({
      ...entry,
      // Keep the plaintext password for the frontend (if necessary)
      password: entry.password,
      extra_fields: {
        extra1: entry.extra_fields?.extra1 || "",
        extra2: entry.extra_fields?.extra2 || "",
        extra3: entry.extra_fields?.extra3 || "",
        extra4: entry.extra_fields?.extra4 || "",
        extra5: entry.extra_fields?.extra5 || "",
      },
    }));

    // Encrypt the passwords in the JSON for saving the file
    const encryptedEntries = decryptedEntries.map((entry: any) => ({
      ...entry,
      password: encryptPasswordWithRSA(entry.password),
    }));

    const encryptedJsonData = JSON.stringify({ entries: encryptedEntries });
    const encryptedData = encryptWithDES(encryptedJsonData, masterPassword);

    // Create a Blob with the encrypted data
    const encryptedBlob = new Blob([encryptedData], {
      type: "application/octet-stream",
    });

    // Prepare the response
    return new Response(encryptedBlob, {
      status: 200,
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": 'attachment; filename="encrypted_passwords.json.enc"',
      },
    });
  } catch (error) {
    console.error("Unexpected error during import:", error);
    return new Response(
      JSON.stringify({ message: "Internal server error" }),
      { status: 500 }
    );
  }
};
