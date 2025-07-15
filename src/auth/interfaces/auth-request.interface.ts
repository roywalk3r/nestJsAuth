import { Request } from 'express';

export interface UserPayload {
  sub: string;
  email: string;
  name: string;
}

export interface AuthRequest extends Request {
  user: UserPayload;
}
