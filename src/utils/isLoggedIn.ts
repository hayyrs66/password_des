import jwt from 'jsonwebtoken';

const jwtSecret = process.env.JWT_SECRET!;

export function isLoggedIn(cookie: string | null): boolean {
  if (!cookie) return false;

  // Extraer el token de la cookie
  const sessionCookie = cookie.split('; ').find(row => row.startsWith('session='));
  if (!sessionCookie) return false;

  const token = sessionCookie.split('=')[1];
  try {
    // Verificar el token JWT
    const decoded = jwt.verify(token, jwtSecret);
    console.log("Token is valid:", decoded);
    return true;
  } catch (error) {
    console.error("Token verification failed:", error);
    return false;
  }
}
