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
      return new Response(JSON.stringify({ message: "All fields are required" }), { status: 400 });
    }

    // Leer y parsear el contenido del archivo JSON plano
    const plainContent = await file.text();
    const jsonData = JSON.parse(plainContent);

    // Encriptar cada contraseña individualmente con RSA y conservar los datos desencriptados
    const decryptedEntries = jsonData.entries.map(entry => ({
      ...entry,
      password: entry.password,  // Contraseña en texto plano para la interfaz
      extra_fields: {
        extra1: entry.extra_fields?.extra1 || "",
        extra2: entry.extra_fields?.extra2 || "",
        extra3: entry.extra_fields?.extra3 || "",
        extra4: entry.extra_fields?.extra4 || "",
        extra5: entry.extra_fields?.extra5 || ""
      }
    }));

    // Encriptar las contraseñas en el JSON para guardar el archivo
    const encryptedEntries = decryptedEntries.map(entry => ({
      ...entry,
      password: encryptPasswordWithRSA(entry.password)
    }));

    const encryptedJsonData = JSON.stringify({ entries: encryptedEntries });
    const encryptedData = encryptWithDES(encryptedJsonData, masterPassword);

    // Responder con la estructura desencriptada y el archivo encriptado
    return new Response(
      JSON.stringify({
        encryptedFile: Buffer.from(encryptedData).toString("base64"),
        decryptedData: decryptedEntries,
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }
    );
  } catch (error) {
    console.error("Unexpected error during import:", error);
    return new Response(JSON.stringify({ message: "Internal server error" }), { status: 500 });
  }
};
