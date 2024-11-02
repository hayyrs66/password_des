process.loadEnvFile();

import type { APIRoute } from "astro";
import crypto from "crypto";

const rsaPublicKey = process.env.RSA_PUBLIC_KEY!;

function deriveDESKeyFromPassword(password: string): Buffer {
  return crypto.pbkdf2Sync(password, "salt", 1000, 8, "sha256");
}
function encryptWithDES(data: string, password: string) {
  const desKey = deriveDESKeyFromPassword(password);
  const cipher = crypto.createCipheriv("des-ecb", desKey, null);
  return Buffer.concat([cipher.update(data, "utf8"), cipher.final()]).toString(
    "base64"
  );
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
  return crypto
    .publicEncrypt(
      {
        key: rsaPublicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(password)
    )
    .toString("base64");
}

export const POST: APIRoute = async ({ request }) => {
  try {
    const formData = await request.formData();

    const master_password = formData.get('new-master-pass') as string;
    const is_encrypted = formData.get('is_encrypted') === 'true';
    const file = formData.get('edit-passfile') as File;

    if (!master_password || !file) {
      return new Response(
        JSON.stringify({ message: 'All fields are required' }),
        { status: 400 }
      );
    }

    let data = { entries: [] as Array<any> };

    try {
      const arrayBuffer = await file.arrayBuffer();
      const fileContent = Buffer.from(arrayBuffer).toString('utf8');

      if (is_encrypted) {
        try {
          const decryptedJson = decryptWithDES(fileContent, master_password);
          data = JSON.parse(decryptedJson);
        } catch (error) {
          console.error('Error decrypting JSON file with DES:', error);
          return new Response(
            JSON.stringify({
              message: 'Failed to decrypt or parse the file',
            }),
            { status: 500 }
          );
        }
      } else {
        data = fileContent ? JSON.parse(fileContent) : { entries: [] };
      }

      if (!Array.isArray(data.entries)) {
        return new Response(
          JSON.stringify({
            message: "Invalid JSON format: 'entries' array is missing",
          }),
          { status: 400 }
        );
      }
    } catch (error) {
      console.error('Error reading file:', error);
      return new Response(
        JSON.stringify({ message: 'Failed to read or parse the file' }),
        { status: 500 }
      );
    }
    const encryptedPassword = encryptPasswordWithRSA(
      formData.get('site-password') as string
    );

    const extra_fields = [];
    for (let i = 1; i <= 5; i++) {
      const field = formData.get(`extra_field_${i}`);
      if (field) {
        extra_fields.push(field);
      }
    }

    const tags = formData.getAll('tags[]');

    data.entries.push({
      id: data.entries.length + 1,
      site_name: formData.get('site-name'),
      username: formData.get('username'),
      password: encryptedPassword,
      url: formData.get('url'),
      notes: formData.get('notes'),
      extra_fields: extra_fields,
      tags: tags,
      creation_date: new Date().toISOString(),
      update_date: new Date().toISOString(),
    });

    const updatedJson = JSON.stringify(data, null, 2);

    // Always encrypt the output data
    const finalData = encryptWithDES(updatedJson, master_password);

    return new Response(finalData, {
      status: 200,
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': 'attachment; filename="updated_passwords.json"',
      },
    });
  } catch (error) {
    console.error('Unexpected error:', error);
    return new Response(
      JSON.stringify({ message: 'Internal server error' }),
      { status: 500 }
    );
  }
};
