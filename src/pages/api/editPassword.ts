// Endpoint: editPassword.ts

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
  return Buffer.concat([
    cipher.update(Buffer.from(data, "utf8")),
    cipher.final(),
  ]);
}

// DES Decryption with ECB mode and PKCS7 padding
function decryptWithDES(encryptedData: Buffer, password: string) {
  const desKey = formatDESKey(password);
  const decipher = crypto.createDecipheriv("des-ecb", desKey, null);
  decipher.setAutoPadding(true);
  const decrypted = Buffer.concat([
    decipher.update(encryptedData),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

// RSA Encryption with PKCS1 v1.5 padding
function encryptPasswordWithRSA(data: string) {
  const buffer = Buffer.from(data, "utf8");
  const encrypted = publicKey.encrypt(
    buffer.toString("binary"),
    "RSAES-PKCS1-V1_5"
  );
  return Buffer.from(encrypted, "binary").toString("base64");
}

export const POST: APIRoute = async ({ request }) => {
  try {
    const formData = await request.formData();
    const masterPassword = formData.get("master_password") as string;
    const file = formData.get("edit-passfile") as File;
    const iconFile = formData.get("icon_file") as File;
    const entryId = parseInt(formData.get("entry_id") as string);

    if (!masterPassword || !file || isNaN(entryId)) {
      return new Response(
        JSON.stringify({ message: "All fields are required" }),
        { status: 400 }
      );
    }

    let data = { entries: [] as Array<any> };
    try {
      const arrayBuffer = await file.arrayBuffer();
      const encryptedBuffer = Buffer.from(arrayBuffer);

      const decryptedJson = decryptWithDES(encryptedBuffer, masterPassword);
      data = JSON.parse(decryptedJson);

      if (!Array.isArray(data.entries)) {
        return new Response(
          JSON.stringify({
            message: "Invalid JSON format: 'entries' array is missing",
          }),
          { status: 400 }
        );
      }
    } catch (error) {
      console.error("Error processing file:", error);
      return new Response(
        JSON.stringify({ message: "Failed to read or parse the file" }),
        { status: 500 }
      );
    }

    // Find the entry to edit
    const entryIndex = data.entries.findIndex((item) => item.id === entryId);
    if (entryIndex === -1) {
      return new Response(
        JSON.stringify({ message: "Password entry not found" }),
        { status: 404 }
      );
    }

    const entry = data.entries[entryIndex];

    // Update fields
    entry.site_name = formData.get("site_name");
    entry.username = formData.get("username");
    entry.url = formData.get("url");
    entry.notes = formData.get("notes");
    entry.update_date = new Date().toISOString();

    // Process tags
    const tagsInput = formData.get("tags") as string;
    entry.tags = tagsInput
      .split(",")
      .map((tag) => tag.trim())
      .filter((tag) => tag !== "");

    // Process extra fields
    const extraFieldsInput = formData.get("extra_fields") as string;
    const extraFieldsArray = extraFieldsInput
      .split(",")
      .map((field) => field.trim());
    const extraFields: { [key: string]: string } = {};
    for (let i = 1; i <= 5; i++) {
      extraFields[`extra${i}`] = extraFieldsArray[i - 1] || "";
    }
    entry.extra_fields = extraFields;

    // If a new password is provided, encrypt it
    const sitePassword = formData.get("site_password") as string;
    if (sitePassword) {
      const encryptedPassword = encryptPasswordWithRSA(sitePassword);
      entry.password = encryptedPassword;
    }

    // If a new icon is provided, validate and encode it as Base64 SVG
    if (iconFile && iconFile.size > 0) {
      // Validate MIME type
      if (iconFile.type !== "image/svg+xml") {
        return new Response(
          JSON.stringify({ message: "Only SVG files are supported for icons." }),
          { status: 400 }
        );
      }

      // Read the content of the SVG file
      const iconArrayBuffer = await iconFile.arrayBuffer();
      const iconBuffer = Buffer.from(iconArrayBuffer);
      const iconBase64 = iconBuffer.toString("base64");

      // Store the Base64 string in entry.icon
      entry.icon = iconBase64;
    }

    // Encrypt and return the updated file
    const updatedJson = JSON.stringify(data, null, 2);
    const finalDataBuffer = encryptWithDES(updatedJson, masterPassword);

    return new Response(finalDataBuffer, {
      status: 200,
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Disposition":
          'attachment; filename="updated_passwords.json.enc"',
      },
    });
  } catch (error) {
    console.error("Unexpected error:", error);
    return new Response(JSON.stringify({ message: "Internal server error" }), {
      status: 500,
    });
  }
};