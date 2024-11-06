process.loadEnvFile();

import type { APIRoute } from "astro";
import crypto from "crypto";

function formatDESKey(password: string) {
  return Buffer.byteLength(password, "utf8") === 8
    ? Buffer.from(password, "utf8")
    : Buffer.from(password.padEnd(8, " "), "utf8");
}

function encryptWithDES(data: string, password: string) {
  const desKey = formatDESKey(password);
  const cipher = crypto.createCipheriv("des-ecb", desKey, null);
  cipher.setAutoPadding(true);
  return Buffer.concat([cipher.update(data, "utf8"), cipher.final()]);
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

    let jsonData;

    // Detectar si el archivo es .json o .json.dec y procesarlo como plano
    if (file.name.endsWith(".json") || file.name.endsWith(".json.dec")) {
      // Tratar ambos archivos como planos
      const plainContent = await file.text();
      try {
        jsonData = JSON.parse(plainContent);
      } catch (error) {
        console.error("Error parsing JSON:", error);
        return new Response(
          JSON.stringify({ message: "Failed to parse JSON file" }),
          { status: 400 }
        );
      }
    } else {
      return new Response(
        JSON.stringify({ message: "Unsupported file format. Use .json or .json.dec" }),
        { status: 400 }
      );
    }

    // Validar que el formato JSON tenga las contraseñas encriptadas con RSA
    if (!jsonData || !Array.isArray(jsonData.entries)) {
      return new Response(
        JSON.stringify({ message: "Invalid JSON format: 'entries' array is missing or not an array" }),
        { status: 400 }
      );
    }

    // Crear una representación JSON en texto de los datos para su encriptación
    const jsonString = JSON.stringify(jsonData);

    // Encriptar el contenido del archivo usando DES con la contraseña maestra
    const encryptedData = encryptWithDES(jsonString, masterPassword);

    // Crear una respuesta con el archivo encriptado
    const encryptedBlob = new Blob([encryptedData], {
      type: "application/octet-stream",
    });

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
