// Endpoint: addPassword
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

// DES Encryption with ECB mode and PKCS7 padding
function encryptWithDES(data: string, password: string) {
  const desKey = formatDESKey(password);
  const cipher = crypto.createCipheriv("des-ecb", desKey, null);
  cipher.setAutoPadding(true);
  return Buffer.concat([cipher.update(Buffer.from(data, "utf8")), cipher.final()]);
}

// DES Decryption with ECB mode and PKCS7 padding
function decryptWithDES(encryptedData: Buffer, password: string) {
  const desKey = formatDESKey(password);
  const decipher = crypto.createDecipheriv("des-ecb", desKey, null);
  decipher.setAutoPadding(true);
  const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
  return decrypted.toString("utf8");
}


// RSA Encryption with PKCS1 v1.5 padding
function encryptPasswordWithRSA(data: string) {
  const buffer = Buffer.from(data, "utf8");
  const encrypted = publicKey.encrypt(buffer.toString("binary"), "RSAES-PKCS1-V1_5");
  return Buffer.from(encrypted, "binary").toString("base64");
}

// Calculate expiration date 5 months after creation
function calculateExpirationDate(creationDate: Date): string {
  const expirationDate = new Date(creationDate);
  expirationDate.setMonth(expirationDate.getMonth() + 5);
  return expirationDate.toISOString();
}

export const POST: APIRoute = async ({ request }) => {
  try {
    const formData = await request.formData();
    const masterPassword = formData.get("new-master-pass") as string;
    const isEncrypted = formData.get("is_encrypted") === "true";
    const file = formData.get("edit-passfile") as File;
    const iconFile = formData.get("edit-icon-file") as File;

    console.log(file, masterPassword, iconFile)

    if (!masterPassword || !file || !iconFile) {
      return new Response(JSON.stringify({ message: "All fields are required" }), { status: 400 });
    }

    let data = { entries: [] as Array<any> };
    try {
      const arrayBuffer = await file.arrayBuffer();
      const encryptedBuffer = Buffer.from(arrayBuffer);

      if (isEncrypted) {
        const decryptedJson = decryptWithDES(encryptedBuffer, masterPassword);
        data = JSON.parse(decryptedJson);
      } else {
        const fileContent = encryptedBuffer.toString("utf8");
        data = fileContent ? JSON.parse(fileContent) : { entries: [] };
      }

      if (!Array.isArray(data.entries)) {
        return new Response(JSON.stringify({ message: "Invalid JSON format: 'entries' array is missing" }), { status: 400 });
      }
    } catch (error) {
      console.error("Error processing file:", error);
      return new Response(JSON.stringify({ message: "Failed to read or parse the file" }), { status: 500 });
    }

    const encryptedPassword = encryptPasswordWithRSA(formData.get("site-password") as string);
    const extraFields = Array.from({ length: 5 }, (_, i) => formData.get(`extra_field_${i + 1}`)).filter(Boolean);
    const tags = formData.getAll("tags[]");
    const creationDate = new Date();
    const expirationDate = calculateExpirationDate(creationDate);

    const iconArrayBuffer = await iconFile.arrayBuffer();
    const iconBase64 = Buffer.from(iconArrayBuffer).toString("base64");

    data.entries.push({
      id: data.entries.length + 1,
      site_name: formData.get("site-name"),
      username: formData.get("username"),
      password: encryptedPassword,
      url: formData.get("url"),
      notes: formData.get("notes"),
      extra_fields: extraFields,
      tags: tags,
      creation_date: creationDate.toISOString(),
      update_date: creationDate.toISOString(),
      expiration_date: expirationDate,
      icon: `data:image/png;base64,${iconBase64}`,
    });

    const updatedJson = JSON.stringify(data, null, 2);
    const finalDataBuffer = encryptWithDES(updatedJson, masterPassword);

    return new Response(finalDataBuffer, {
      status: 200,
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": 'attachment; filename="updated_passwords.json.enc"',
      },
    });
  } catch (error) {
    console.error("Unexpected error:", error);
    return new Response(JSON.stringify({ message: "Internal server error" }), { status: 500 });
  }
};
