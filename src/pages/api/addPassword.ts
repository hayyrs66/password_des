import type { APIRoute } from "astro";
import fs from "fs/promises";
import path from "path";
import crypto from "crypto";
import { publicEncrypt } from "crypto";

const jsonFilePath = path.join(process.cwd(), "passwords.json");
const desKey = process.env.DES_KEY!;
const rsaPublicKey = process.env.RSA_PUBLIC_KEY!;

function encryptWithDES(data: string) {
  const cipher = crypto.createCipheriv("des-ecb", Buffer.from(desKey), null);
  return Buffer.concat([cipher.update(data, "utf8"), cipher.final()]).toString("base64");
}

function decryptWithDES(encryptedData: string) {
  const decipher = crypto.createDecipheriv("des-ecb", Buffer.from(desKey), null);
  return Buffer.concat([decipher.update(Buffer.from(encryptedData, "base64")), decipher.final()]).toString("utf8");
}

function encryptPasswordWithRSA(password: string) {
  return publicEncrypt(rsaPublicKey, Buffer.from(password)).toString("base64");
}

export const POST: APIRoute = async ({ request }) => {
  try {
    const body = await request.json();

    body.password = encryptPasswordWithRSA(body.password);
    let encryptedJson = await fs.readFile(jsonFilePath, "utf8");
    let decryptedJson = decryptWithDES(encryptedJson);
    let data = JSON.parse(decryptedJson);

    data.entries.push({
      id: data.entries.length + 1,
      ...body,
      creation_date: new Date().toISOString(),
      update_date: new Date().toISOString(),
    });

    const updatedJson = JSON.stringify(data, null, 2);
    encryptedJson = encryptWithDES(updatedJson);
    await fs.writeFile(jsonFilePath, encryptedJson, "utf8");

    return new Response(JSON.stringify({ message: "Password added successfully" }), {
      status: 200,
    });
  } catch (error) {
    console.error("Error adding password:", error);
    return new Response(JSON.stringify({ message: "Failed to add password" }), {
      status: 500,
    });
  }
};
