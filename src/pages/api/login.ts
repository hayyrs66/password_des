process.loadEnvFile();
import type { APIRoute } from "astro";
import { createClient } from "@supabase/supabase-js";
import argon2 from "argon2";
import jwt from "jsonwebtoken";

// Configuración de Supabase
const supabaseUrl = process.env.SUPABASE_URL!;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY!;
const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Clave secreta para firmar el JWT (guárdala en una variable de entorno)
const jwtSecret = process.env.JWT_SECRET!;

export const POST: APIRoute = async ({ request, cookies }) => {
  if (request.headers.get("content-type") !== "application/json") {
    return new Response(JSON.stringify({ error: "Invalid content type" }), {
      status: 400,
    });
  }

  const { email, password } = await request.json();

  // Verificar que los campos estén presentes
  if (!email || !password) {
    return new Response(JSON.stringify({ error: "Email and password are required" }), {
      status: 400,
    });
  }

  // Obtener usuario de Supabase
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
    httpOnly: true, // La cookie no es accesible desde JavaScript
    secure: true,   // Solo se envía por HTTPS
    sameSite: "strict", // Protección CSRF
    maxAge: 3600,   // Duración de la cookie (en segundos)
    path: "/",      // Disponible en toda la aplicación
  });

  return new Response(JSON.stringify({ message: "Login successful" }), {
    status: 200,
  });
};
