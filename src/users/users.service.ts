import { Injectable } from '@nestjs/common';
import { PrismaService } from '@/prisma/prisma.service';
import { AuthCredentialsDto } from '@/auth/dto/auth-credentials.dto';
import * as bcrypt from 'bcrypt';
import { User, RefreshToken } from '~/prisma/generated/prisma/client';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async createUser(authCredentialsDto: AuthCredentialsDto): Promise<void> {
    const { email, password, name } = authCredentialsDto;

    // Check if user already exists
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new Error('User with this email already exists');
    }

    async function hashPassword(password: string): Promise<string | null> {
      try {
        const salt = await bcrypt.genSalt();
        return await bcrypt.hash(password, salt);
      } catch (error: unknown) {
        if (error instanceof Error) {
          console.error('Error hashing password:', error.message);
        } else {
          console.error('Unknown error during hashing.');
        }
        return null;
      }
    }

    const hashedPassword = await hashPassword(password);

    if (hashedPassword === null) {
      throw new Error('Failed to hash password');
    }

    try {
      await this.prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          name,
        },
      });
    } catch (error) {
      console.error('Error creating user:', error);
      throw new Error('Failed to create user');
    }
  }

  async findByEmail(
    email: string,
  ): Promise<(User & { refreshTokens: RefreshToken[] }) | null> {
    const user = await this.prisma.user.findUnique({
      where: { email },
      include: {
        refreshTokens: true,
      },
    });

    if (!user) {
      return null;
    }

    return user;
  }

  async findById(
    id: string,
  ): Promise<(User & { refreshTokens: RefreshToken[] }) | null> {
    const user = await this.prisma.user.findUnique({
      where: { id },
      include: {
        refreshTokens: true,
      },
    });

    if (!user) {
      return null;
    }

    return user;
  }

  async setCurrentRefreshToken(
    refreshToken: string,
    userId: string,
  ): Promise<(User & { refreshTokens: RefreshToken[] }) | null> {
    // Get the current user
    const user = await this.findById(userId);

    if (!user) {
      return null;
    }

    try {
      const hashedRefreshToken: string = await bcrypt.hash(refreshToken, 10);
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7); // The Token expires in 7 days

      await this.prisma.refreshToken.create({
        data: {
          token: hashedRefreshToken,
          userId,
          expiresAt,
        },
      });
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error('Error setting refresh token:', error.message);
      } else {
        console.error('Unknown error occurred while setting refresh token');
      }
      // Return null to indicate failure
      return null; //Error('Failed to set refresh token');
    }

    return this.findById(userId);
  }

  async removeRefreshToken(userId: string, refreshToken?: string) {
    // Get the current user
    const user = await this.findById(userId);

    if (!user) {
      return null;
    }

    if (refreshToken) {
      // Find the matching refresh token
      const matchingToken = await this.findRefreshTokenByValue(
        userId,
        refreshToken,
      );

      if (matchingToken) {
        // Mark the token as revoked
        await this.prisma.refreshToken.update({
          where: { id: matchingToken.id },
          data: { revoked: true },
        });
      }
    } else {
      // Mark all tokens as revoked
      await this.prisma.refreshToken.updateMany({
        where: { userId: userId },
        data: { revoked: true },
      });
    }

    // Return the updated user
    // return this.findById(userId);
    // Return a success message
    return { message: 'Refresh tokens revoked successfully' };
  }

  private async findRefreshTokenByValue(userId: string, refreshToken: string) {
    const userWithTokens = await this.findById(userId);

    if (!userWithTokens || !userWithTokens.refreshTokens.length) {
      return null;
    }

    // Check each token to find a match
    for (const tokenObj of userWithTokens.refreshTokens) {
      const isRefreshTokenMatching = await bcrypt.compare(
        refreshToken,
        tokenObj.token,
      );

      if (isRefreshTokenMatching && !tokenObj.revoked) {
        return tokenObj;
      }
    }

    return null;
  }

  async getUserIfRefreshTokenMatches(refreshToken: string, userId: string) {
    // Find the matching token
    const matchingToken = await this.findRefreshTokenByValue(
      userId,
      refreshToken,
    );

    if (matchingToken) {
      return this.findById(userId);
    }

    return null;
  }

  async validatePassword(user: User, password: string): Promise<boolean> {
    return bcrypt.compare(password, user.password);
  }
}
