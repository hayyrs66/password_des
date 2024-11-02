process.loadEnvFile();
import type { APIRoute } from "astro";
import { createClient } from "@supabase/supabase-js";
import argon2 from "argon2";
import jwt from "jsonwebtoken";

const supabaseUrl = process.env.SUPABASE_URL!;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY!;
const supabase = createClient(supabaseUrl, supabaseAnonKey);

const jwtSecret = process.env.JWT_SECRET!;

export const POST: APIRoute = async ({ request, cookies }) => {
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

  const token = jwt.sign(
    { userId: user.id, email: user.email },
    jwtSecret,
    { expiresIn: "1h" }
  );

  cookies.set("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 3600,
    path: "/",
  });

  return new Response(JSON.stringify({ message: "Login successful" }), {
    status: 200,
  });
};
