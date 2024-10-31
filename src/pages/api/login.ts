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

  const { data: user, error } = await supabase
    .from("users")
    .select("id, email, hashed_master_password")
    .eq("email", email)
    .single();

  if (error || !user) {
    return new Response(JSON.stringify({ error: "User not found" }), { status: 404 });
  }
  const isPasswordValid = await argon2.verify(user.hashed_master_password, password);
  if (!isPasswordValid) {
    return new Response(JSON.stringify({ error: "Invalid password" }), { status: 401 });
  }

  return new Response(JSON.stringify({ message: "Login successful", userId: user.id }), {
    status: 200,
  });
};
