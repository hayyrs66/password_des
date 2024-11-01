import type { APIRoute } from "astro";
import fs from "fs/promises";
import path from "path";
import crypto from "crypto";
import { publicEncrypt } from "crypto";

const jsonFilePath = path.join(process.cwd(), "passwords.json");
const rsaPublicKey = process.env.RSA_PUBLIC_KEY!;

function deriveDESKeyFromPassword(password: string): Buffer {
  return crypto.pbkdf2Sync(password, "salt", 1000, 8, "sha256");
}

function encryptWithDES(data: string, password: string) {
  const desKey = deriveDESKeyFromPassword(password);
  const cipher = crypto.createCipheriv("des-ecb", desKey, null);
  return Buffer.concat([cipher.update(data, "utf8"), cipher.final()]).toString("base64");
}

function decryptWithDES(encryptedData: string, password: string) {
  const desKey = deriveDESKeyFromPassword(password);
  const decipher = crypto.createDecipheriv("des-ecb", desKey, null);
  return Buffer.concat([
    decipher.update(Buffer.from(encryptedData, "base64")),
    decipher.final(),
  ]).toString("utf8");
}

function encryptPasswordWithRSA(password: string) {
  return crypto.publicEncrypt(
    {
      key: rsaPublicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(password)
  ).toString("base64");
}


export const POST: APIRoute = async ({ request }) => {
  try {
    const body = await request.json();
    console.log("Received data:", body);

    if (!body.master_password) {
      console.error("Master password is missing.");
      return new Response(JSON.stringify({ message: "Master password is required" }), { status: 400 });
    }

    // Encriptar la contraseña con RSA
    try {
      body.password = encryptPasswordWithRSA(body.password);
      console.log("Password encrypted with RSA.");
    } catch (error) {
      console.error("Error encrypting password with RSA:", error);
      return new Response(JSON.stringify({ message: "Encryption error" }), { status: 500 });
    }

    const masterPassword = body.master_password;
    delete body.master_password;

    // Verificar si el archivo JSON existe
    let encryptedJson;
    let data = { entries: [] as Array<any> };

    try {
      encryptedJson = await fs.readFile(jsonFilePath, "utf8");
      const decryptedJson = decryptWithDES(encryptedJson, masterPassword);
      console.log("File decrypted with DES.");
      data = JSON.parse(decryptedJson);
    } catch (error) {
      if (error.code === "ENOENT") {
        console.log("File does not exist. Creating a new encrypted JSON file.");
      } else {
        console.error("Error reading or decrypting JSON file:", error);
        return new Response(JSON.stringify({ message: "Error reading data file" }), { status: 500 });
      }
    }

    // Agregar la nueva entrada
    data.entries.push({
      id: data.entries.length + 1,
      ...body,
      creation_date: new Date().toISOString(),
      update_date: new Date().toISOString(),
    });

    // Encriptar y guardar el archivo actualizado
    try {
      const updatedJson = JSON.stringify(data, null, 2);
      console.log("Data to be encrypted with DES:", updatedJson);

      encryptedJson = encryptWithDES(updatedJson, masterPassword);
      console.log("Data encrypted successfully. Saving to file...");

      await fs.writeFile(jsonFilePath, encryptedJson, "utf8");
      console.log("File encrypted and saved.");
    } catch (error) {
      console.error("Error encrypting or saving JSON file:", error);
      return new Response(JSON.stringify({ message: "Error saving data" }), { status: 500 });
    }

    return new Response(JSON.stringify({ message: "Password added successfully" }), { status: 200 });
  } catch (error) {
    console.error("Unexpected error:", error);
    return new Response(JSON.stringify({ message: "Internal server error" }), { status: 500 });
  }
};
