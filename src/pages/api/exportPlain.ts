process.loadEnvFile();

import type { APIRoute } from "astro";
import crypto from "crypto";
import forge from "node-forge";

// Llave privada RSA, pero en este caso no se utiliza para desencriptar las contraseñas individuales
const rsaPrivateKey = process.env.RSA_PRIVATE_KEY!;
const privateKey = forge.pki.privateKeyFromPem(rsaPrivateKey);

function formatDESKey(password: string) {
  return Buffer.byteLength(password, "utf8") === 8
    ? Buffer.from(password, "utf8")
    : Buffer.from(password.padEnd(8, " "), "utf8");
}

function decryptWithDES(encryptedData: Buffer, password: string) {
  const desKey = formatDESKey(password);
  const decipher = crypto.createDecipheriv("des-ecb", desKey, null);
  decipher.setAutoPadding(true);
  return Buffer.concat([decipher.update(encryptedData), decipher.final()]).toString();
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

    // Desencriptar el archivo con DES usando la contraseña maestra
    const encryptedBuffer = await file.arrayBuffer();
    const encryptedData = Buffer.from(encryptedBuffer);
    const decryptedData = decryptWithDES(encryptedData, masterPassword);

    let jsonData;
    try {
      jsonData = JSON.parse(decryptedData);
    } catch (error) {
      console.error("Error parsing JSON:", error);
      return new Response(
        JSON.stringify({ message: "Failed to parse JSON file" }),
        { status: 400 }
      );
    }

    // Mantener las contraseñas con RSA sin desencriptarlas
    const plainEntries = jsonData.entries.map((entry: any) => ({
      ...entry,
      password: entry.password, // Mantener la encriptación RSA en la contraseña
    }));

    // Crear el JSON en texto plano para exportar
    const plainData = JSON.stringify({ entries: plainEntries }, null, 2);

    // Preparar el archivo para la respuesta
    return new Response(plainData, {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": 'attachment; filename="passwords_plain.json"',
      },
    });
  } catch (error) {
    console.error("Unexpected error during export:", error);
    return new Response(
      JSON.stringify({ message: "Internal server error" }),
      { status: 500 }
    );
  }
};
