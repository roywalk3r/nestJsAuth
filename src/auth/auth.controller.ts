import { Body, Controller, Post, Get, UseGuards, Req } from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from './auth.service';
import {
  AuthCredentialsDto,
  LoginCredentialsDto,
  RefreshTokenDto,
} from './dto/auth-credentials.dto';
import { AuthResponseDto } from './dto/auth-response.dto';
import { JwtAuthGuard } from './auth.guard';
import { AuthRequest, UserPayload } from './interfaces/auth-request.interface';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/signup')
  async signUp(@Body() authCredentialsDto: AuthCredentialsDto): Promise<void> {
    return this.authService.signUp(authCredentialsDto);
  }

  @Post('/signin')
  async signIn(
    @Body() loginCredentialsDto: LoginCredentialsDto,
  ): Promise<AuthResponseDto> {
    return this.authService.signIn(loginCredentialsDto);
  }

  @Post('/refresh')
  async refreshTokens(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshTokens(refreshTokenDto);
  }

  @Post('/logout')
  @UseGuards(JwtAuthGuard)
  async logout(
    @Req() req: AuthRequest,
    @Body() body: { refreshToken?: string },
  ) {
    const userId = req.user.sub;
    return this.authService.logout(userId, body.refreshToken);
  }

  @Post('/logout-all')
  @UseGuards(JwtAuthGuard)
  async logoutAll(@Req() req: AuthRequest) {
    const userId = req.user.sub;
    return this.authService.logoutAll(userId);
  }

  @Get('/me')
  @UseGuards(JwtAuthGuard)
  getProfile(@Req() req: AuthRequest): UserPayload {
    return req.user;
  }
}
