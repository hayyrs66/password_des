import jwt from 'jsonwebtoken';

const jwtSecret = process.env.JWT_SECRET!;

export function isLoggedIn(cookie: string | null): boolean {
  if (!cookie) return false;

  const sessionCookie = cookie.split('; ').find(row => row.startsWith('session='));
  if (!sessionCookie) return false;

  const token = sessionCookie.split('=')[1];
  try {
    jwt.verify(token, jwtSecret);
    return true;
  } catch (error) {
    return false;
  }
}
