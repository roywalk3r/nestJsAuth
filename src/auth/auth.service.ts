import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { LoginCredentialsDto } from './dto/auth-credentials.dto';
import { RefreshTokenDto } from './dto/auth-credentials.dto';
import { AuthResponseDto } from './dto/auth-response.dto';
import { UserService } from '@/users/users.service';
import { jwtConstants } from '@/config/jwt.config';
import { JwtPayload } from '@/auth/interfaces/jwt-payload.interface';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
  ) {}

  async signUp(authCredentialsDto: AuthCredentialsDto): Promise<void> {
    try {
      await this.userService.createUser(authCredentialsDto);
    } catch (error) {
      if (error.message === 'User with this email already exists') {
        throw new UnauthorizedException(
          'A user with this email already exists',
        );
      }
      throw error;
    }
  }

  async signIn(
    loginCredentialsDto: LoginCredentialsDto,
  ): Promise<AuthResponseDto> {
    const { email, password } = loginCredentialsDto;
    const user = await this.userService.findByEmail(email);

    if (user && (await this.userService.validatePassword(user, password))) {
      const tokens = await this.getTokens(user.id, user.email);
      await this.updateRefreshToken(user.id, tokens.refreshToken);
      return {
        ...tokens,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
      };
    } else {
      throw new UnauthorizedException('Please check your login credentials');
    }
  }

  async refreshTokens(refreshTokenDto: RefreshTokenDto) {
    try {
      const { refreshToken } = refreshTokenDto;
      const payload: JwtPayload = await this.jwtService.verifyAsync(
        refreshToken,
        {
          secret: jwtConstants.refreshTokenSecret,
        },
      );

      const user = await this.userService.getUserIfRefreshTokenMatches(
        refreshToken,
        payload.sub,
      );

      if (!user) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Remove the old refresh token
      await this.userService.removeRefreshToken(user.id, refreshToken);

      // Generate new tokens
      const tokens = await this.getTokens(user.id, user.email);

      // Add the new refresh token
      await this.updateRefreshToken(user.id, tokens.refreshToken);

      return {
        ...tokens,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async logout(userId: string, refreshToken?: string) {
    return this.userService.removeRefreshToken(userId, refreshToken);
  }

  async logoutAll(userId: string) {
    return this.userService.removeRefreshToken(userId);
  }

  private async updateRefreshToken(userId: string, refreshToken: string) {
    await this.userService.setCurrentRefreshToken(refreshToken, userId);
  }

  private async getTokens(userId: string, email: string) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: jwtConstants.accessTokenSecret,
          expiresIn: jwtConstants.accessTokenExpiration,
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: jwtConstants.refreshTokenSecret,
          expiresIn: jwtConstants.refreshTokenExpiration,
        },
      ),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }
}
