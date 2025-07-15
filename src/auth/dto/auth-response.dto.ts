import { PartialType } from '@nestjs/mapped-types';
import { AuthCredentialsDto } from './auth-credentials.dto';

// export class AuthResponseDto extends PartialType(AuthCredentialsDto) {}
export class AuthResponseDto {
  accessToken: string;
  refreshToken: string;
  user: {
    id: string;
    email: string;
    name: string;
  };
}
