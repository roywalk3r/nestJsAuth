import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { jwtConstants } from '@/config/jwt.config';
import { JwtPayload } from '@/jwt-payload/jwt-payload.interface';
import { AuthService } from '@/auth/auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtConstants.accessTokenSecret,
    });
  }

  private readonly logger = new Logger(JwtStrategy.name);

  validate(payload: JwtPayload) {
    try {
      if (!payload.sub || !payload.email) {
        throw new UnauthorizedException('Invalid token: Missing user');
      }

      return {
        sub: payload.sub,
        email: payload.email,
        username: payload.email, // Using email as username since it's unique
      };
    } catch (error) {
      this.logger.error(`JWT validation error: ${error.message}`, error.stack);
      throw new UnauthorizedException('Invalid token');
    }
  }
}
