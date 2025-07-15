import {
  ExecutionContext,
  Injectable,
  Logger,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger(JwtAuthGuard.name);

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const canActivate = (await super.canActivate(context)) as boolean;

    if (!canActivate) {
      this.logger.warn('Access denied by base AuthGuard');
      return false;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      this.logger.warn('Authenticated but user payload is missing in request');
    } else {
      this.logger.debug(`Authenticated user: ${user.email ?? user.username ?? user.id}`);
    }

    return true;
  }
}
