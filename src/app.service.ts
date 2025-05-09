import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AppService implements OnModuleInit {
  private readonly logger = new Logger(AppService.name);
  private cachedPublicIp: string | null = null;

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {}

  async onModuleInit() {
    await this.fetchAndCachePublicIp();
  }

  private async fetchAndCachePublicIp(): Promise<void> {
    try {
      const envIp = this.configService.get<string>('SERVER_PUBLIC_IP');
      if (envIp) {
        this.cachedPublicIp = envIp;
        this.logger.log(`Using public IP from environment variable: ${this.cachedPublicIp}`);
        return;
      }

      const response = await firstValueFrom(
        this.httpService.get<string>('https://api.ipify.org'),
      );
      this.cachedPublicIp = response.data;
      this.logger.log(`Fetched and cached public IP: ${this.cachedPublicIp}`);
    } catch (error) {
      this.logger.error(
        'Failed to fetch public IP from api.ipify.org. Falling back to localhost.',
        error.stack,
      );
      this.cachedPublicIp = 'localhost';
    }
  }

  getPublicIp(): string | null {
    return this.cachedPublicIp;
  }

  getHello(): string {
    return 'Hello World!';
  }

  getRpcUrl(): string {
    const rpcPort = this.configService.get<string>('RPC_PORT') || 'UNKNOWN_RPC_PORT';
    const ip = this.getPublicIp() || 'localhost';
    return `http://${ip}:${rpcPort}`;
  }

  getGeyserUrl(): string {
    const geyserPort = this.configService.get<string>('GEYSER_PORT') || 'UNKNOWN_GEYSER_PORT';
    const ip = this.getPublicIp() || 'localhost';
    return `http://${ip}:${geyserPort}`;
  }
}
