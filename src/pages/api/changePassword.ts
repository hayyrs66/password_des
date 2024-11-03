import type { APIRoute } from "astro";
import crypto from "crypto";

function formatDESKey(password) {
  return Buffer.from(password.slice(0, 8), "utf8");
}

function decryptWithDES(encryptedBuffer, password) {
  const desKey = formatDESKey(password);
  const decipher = crypto.createDecipheriv("des-ecb", desKey, null);
  decipher.setAutoPadding(true);
  return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]).toString("utf8");
}

function encryptWithDES(data, password) {
  const desKey = formatDESKey(password);
  const cipher = crypto.createCipheriv("des-ecb", desKey, null);
  cipher.setAutoPadding(true);
  return Buffer.concat([cipher.update(Buffer.from(data, "utf8")), cipher.final()]);
}

export const POST: APIRoute = async ({ request }) => {
  try {
    const formData = await request.formData();
    const oldPassword = formData.get("old_password") as string;
    const newPassword = formData.get("new_password") as string;
    const file = formData.get("file") as File;

    if (!oldPassword || !newPassword || !file) {
      return new Response(JSON.stringify({ message: "All fields are required" }), { status: 400 });
    }

    const encryptedArrayBuffer = await file.arrayBuffer();
    const encryptedBuffer = Buffer.from(encryptedArrayBuffer);

    let decryptedJson;
    try {
      // Decrypt with the old password
      decryptedJson = decryptWithDES(encryptedBuffer, oldPassword);
      console.log("File decrypted successfully with the old password.");
    } catch (error) {
      console.error("Error decrypting file with the old password:", error);
      return new Response(JSON.stringify({ message: "Old password is incorrect" }), { status: 403 });
    }

    // Parse decrypted data
    const data = JSON.parse(decryptedJson);

    // Re-encrypt with the new password
    const reEncryptedData = encryptWithDES(JSON.stringify(data), newPassword);

    return new Response(reEncryptedData, {
      status: 200,
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": "attachment; filename=\"updated_passwords.json.enc\"",
      },
    });
  } catch (error) {
    console.error("Unexpected error:", error);
    return new Response(JSON.stringify({ message: "Internal server error" }), { status: 500 });
  }
};