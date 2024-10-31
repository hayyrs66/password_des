process.loadEnvFile();


import type { APIRoute } from "astro";
import { createClient } from "@supabase/supabase-js";
import argon2 from "argon2";

const supabaseUrl = process.env.SUPABASE_URL!;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY!;
const supabase = createClient(supabaseUrl, supabaseAnonKey);

export const POST: APIRoute = async ({ request }) => {
  if (request.headers.get("content-type") !== "application/json") {
    return new Response(JSON.stringify({ error: "Invalid content type" }), {
      status: 400,
    });
  }

  const { email, password } = await request.json();

  if (!email || !password) {
    return new Response(JSON.stringify({ error: "Email and password are required" }), {
      status: 400,
    });
  }

  const { data: existingUser, error: userFetchError } = await supabase
    .from("users")
    .select("id")
    .eq("email", email)
    .single();

  if (existingUser) {
    return new Response(JSON.stringify({ error: "User already exists" }), {
      status: 409,
    });
  }

  try {
    // Hashear la contraseña usando argon2
    const hashedPassword = await argon2.hash(password);

    // Intentar insertar el nuevo usuario en la base de datos
    const { error: insertError } = await supabase.from("users").insert([
      {
        email,
        hashed_master_password: hashedPassword,
      },
    ]);

    if (insertError) {
      return new Response(JSON.stringify({ error: `Error creating user: ${insertError.message}` }), {
        status: 500,
      });
    }

    return new Response(JSON.stringify({ message: "User registered successfully" }), { status: 201 });
  } catch (err) {
    return new Response(JSON.stringify({ error: "Server error during registration" }), { status: 500 });
  }
};