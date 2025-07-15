import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '~/prisma/generated/prisma/client';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  constructor() {
    super();
  }

  async onModuleInit(): Promise<void> {
    await this.$connect();
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }

  /**
   * Safely deep clones an object and returns plain JSON-safe structure
   */
  cleanupData<T>(data: T): T {
    return JSON.parse(JSON.stringify(data)) as T;
  }

  // No longer needed as refreshTokens are now stored in a separate table
}
