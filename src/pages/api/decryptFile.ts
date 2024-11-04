// decryptFile.ts

process.loadEnvFile();

import type { APIRoute } from "astro";
import crypto from "crypto";
import forge from "node-forge";

// Cargar la clave pública RSA desde las variables de entorno
const rsaPublicKey = process.env.RSA_PUBLIC_KEY!;
const publicKey = forge.pki.publicKeyFromPem(rsaPublicKey);

// Función para formatear la clave DES a 8 bytes
function formatDESKey(password: string) {
  return Buffer.byteLength(password, "utf8") === 8
    ? Buffer.from(password, "utf8")
    : Buffer.from(password.padEnd(8, " "), "utf8");
}

// Función para desencriptar datos con DES
function decryptWithDES(encryptedData: Buffer, password: string) {
  const desKey = formatDESKey(password);
  const decipher = crypto.createDecipheriv("des-ecb", desKey, null);
  decipher.setAutoPadding(true);
  return Buffer.concat([decipher.update(encryptedData), decipher.final()]);
}

export const POST: APIRoute = async ({ request }) => {
  try {
    // Obtener los datos del formulario
    const formData = await request.formData();
    const masterPassword = formData.get("master_password") as string;
    const file = formData.get("file") as File;

    console.log("Received master password:", masterPassword);
    console.log("Received file:", file);

    // Validar que se haya proporcionado la contraseña maestra y el archivo
    if (!masterPassword || !file) {
      return new Response(
        JSON.stringify({ message: "Master password and file are required" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Leer el archivo encriptado
    const arrayBuffer = await file.arrayBuffer();
    const encryptedBuffer = Buffer.from(arrayBuffer);
    console.log("Encrypted data length:", encryptedBuffer.length);

    // Desencriptar el archivo con DES
    let decryptedData: string;
    try {
      decryptedData = decryptWithDES(encryptedBuffer, masterPassword).toString(
        "utf8"
      );
      console.log("Decrypted data:", decryptedData);
    } catch (decryptError) {
      console.error("Error decrypting data:", decryptError);
      return new Response(
        JSON.stringify({
          message: "Failed to decrypt the file. Check your password.",
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Validar que el JSON desencriptado sea válido
    try {
      const json = JSON.parse(decryptedData);
      if (!json.entries || !Array.isArray(json.entries)) {
        throw new Error("Invalid JSON structure");
      }
      console.log("Decrypted JSON is valid.");
    } catch (parseError) {
      console.error("Error parsing decrypted JSON:", parseError);
      return new Response(
        JSON.stringify({ message: "Decrypted file is not a valid JSON" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Crear un Blob con los datos desencriptados
    const decryptedBlob = new Blob([decryptedData], {
      type: "application/json",
    });

    // Preparar la respuesta para descargar el archivo desencriptado
    const response = new Response(decryptedBlob, {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="${file.name.replace(
          /\.enc$/,
          ".dec"
        )}"`,
      },
    });

    return response;
  } catch (error) {
    console.error("Unexpected error during decryptFile:", error);
    return new Response(JSON.stringify({ message: "Internal server error" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
};
