process.loadEnvFile();

import type { APIRoute } from "astro";
import crypto from "crypto";

// Function to format the DES key to 8 bytes
function formatDESKey(password: string) {
  return Buffer.byteLength(password, "utf8") === 8
    ? Buffer.from(password, "utf8")
    : Buffer.from(password.padEnd(8, " "), "utf8");
}

// DES decryption function
function decryptWithDES(encryptedData: Buffer, password: string) {
  const desKey = formatDESKey(password);
  const decipher = crypto.createDecipheriv("des-ecb", desKey, null);
  decipher.setAutoPadding(true);
  return Buffer.concat([decipher.update(encryptedData), decipher.final()]);
}

// Endpoint to decrypt and filter selected entries
export const POST: APIRoute = async ({ request }) => {
  try {
    const formData = await request.formData();
    const encryptedFile = formData.get("file") as Blob;
    const masterPassword = formData.get("master_password") as string;
    const selectedEntries = JSON.parse(formData.get("selected_entries") as string);

    if (!masterPassword || !selectedEntries || !Array.isArray(selectedEntries)) {
      return new Response(
        JSON.stringify({ message: "Master password and selected entries are required." }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Convert the Blob file to a Buffer
    const arrayBuffer = await encryptedFile.arrayBuffer();
    const encryptedData = Buffer.from(arrayBuffer);

    // Decrypt the file using the master password
    let decryptedData;
    try {
      decryptedData = decryptWithDES(encryptedData, masterPassword).toString("utf8");
    } catch (error) {
      console.error("Error decrypting file:", error);
      return new Response(
        JSON.stringify({ message: "Decryption failed. Check your password." }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Parse the decrypted data and filter entries by ID
    let parsedData;
    try {
      parsedData = JSON.parse(decryptedData);
      parsedData.entries = parsedData.entries.filter((entry: any) =>
        selectedEntries.includes(entry.id.toString())
      );
    } catch (error) {
      console.error("Error parsing decrypted data:", error);
      return new Response(
        JSON.stringify({ message: "Invalid decrypted JSON structure." }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Create a Blob with the filtered decrypted data
    const resultBlob = new Blob([JSON.stringify(parsedData, null, 2)], {
      type: "application/json",
    });

    // Return the filtered entries as a downloadable .dec JSON file
    return new Response(resultBlob, {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": 'attachment; filename="selected_entries.dec.json"',
      },
    });
  } catch (error) {
    console.error("Unexpected error in selectDecrypt:", error);
    return new Response(JSON.stringify({ message: "Internal server error" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
};
