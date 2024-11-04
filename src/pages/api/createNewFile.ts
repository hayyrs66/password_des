// createNewFile.ts

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

// Función para encriptar datos con DES
function encryptWithDES(data: string, password: string) {
  const desKey = formatDESKey(password);
  const cipher = crypto.createCipheriv("des-ecb", desKey, null);
  cipher.setAutoPadding(true);
  return Buffer.concat([
    cipher.update(Buffer.from(data, "utf8")),
    cipher.final(),
  ]);
}

// Función para encriptar contraseñas individuales con RSA
function encryptPasswordWithRSA(data: string) {
  const buffer = Buffer.from(data, "utf8");
  const encrypted = publicKey.encrypt(
    buffer.toString("binary"),
    "RSAES-PKCS1-V1_5"
  );
  return Buffer.from(encrypted, "binary").toString("base64");
}

// Función para calcular la fecha de expiración (5 meses después de la fecha de creación)
function calculateExpirationDate(creationDate: Date): string {
  const expirationDate = new Date(creationDate);
  expirationDate.setMonth(expirationDate.getMonth() + 5);
  return expirationDate.toISOString();
}

export const POST: APIRoute = async ({ request }) => {
  try {
    // Obtener los datos del formulario
    const formData = await request.formData();
    const masterPassword = formData.get("master_password") as string;

    // Validar que se haya proporcionado la contraseña maestra
    if (!masterPassword) {
      return new Response(
        JSON.stringify({ message: "Master password is required" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Obtener los demás campos del formulario
    const siteName = formData.get("site_name") as string;
    const username = formData.get("username") as string;
    const sitePassword = formData.get("site_password") as string;
    const url = formData.get("url") as string;
    const notes = formData.get("notes") as string;
    const tagsInput = formData.get("tags") as string;
    const extraFieldsInput = formData.get("extra_fields") as string;
    const iconFile = formData.get("icon_file") as File;

    // Validar que se hayan proporcionado los campos necesarios
    if (
      !siteName ||
      !username ||
      !sitePassword ||
      !url ||
      !notes ||
      !tagsInput ||
      !extraFieldsInput
    ) {
      return new Response(
        JSON.stringify({ message: "All fields are required" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Procesar tags
    const tags = tagsInput
      .split(",")
      .map((tag) => tag.trim())
      .filter((tag) => tag !== "");

    // Procesar extra_fields
    const extraFieldsArray = extraFieldsInput
      .split(",")
      .map((field) => field.trim());
    const extraFields: { [key: string]: string } = {};
    for (let i = 1; i <= 5; i++) {
      extraFields[`extra${i}`] = extraFieldsArray[i - 1] || "";
    }

    // Encriptar la contraseña individual con RSA
    const encryptedPassword = encryptPasswordWithRSA(sitePassword);

    // Obtener la fecha de creación y expiración
    const creationDate = new Date();
    const expirationDate = calculateExpirationDate(creationDate);

    // Procesar el icono si está presente
    let iconBase64 = "";
    if (iconFile) {
      const iconArrayBuffer = await iconFile.arrayBuffer();
      iconBase64 = Buffer.from(iconArrayBuffer).toString("base64");
    }

    // Crear la entrada inicial
    const newEntry = {
      id: 1,
      site_name: siteName,
      username: username,
      password: encryptedPassword,
      url: url,
      notes: notes,
      extra_fields: extraFields,
      tags: tags,
      creation_date: creationDate.toISOString(),
      update_date: creationDate.toISOString(),
      expiration_date: expirationDate,
      icon: iconBase64 ? `data:image/png;base64,${iconBase64}` : "",
    };

    // Crear la estructura de datos con la entrada inicial
    const jsonData = {
      entries: [newEntry],
    };

    // Convertir el JSON a string
    const jsonString = JSON.stringify(jsonData, null, 2);

    // Encriptar el JSON completo con DES utilizando la contraseña maestra
    const encryptedData = encryptWithDES(jsonString, masterPassword);

    // Crear un Blob con los datos encriptados
    const blob = new Blob([encryptedData], {
      type: "application/octet-stream",
    });

    // Preparar la respuesta para descargar el archivo encriptado
    return new Response(blob, {
      status: 200,
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Disposition":
          'attachment; filename="encrypted_passwords.json.enc"',
      },
    });
  } catch (error) {
    console.error("Unexpected error during createNewFile:", error);
    return new Response(
      JSON.stringify({ message: "Internal server error" }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
};
