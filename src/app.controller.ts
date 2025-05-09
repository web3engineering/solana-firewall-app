import { Controller, Get, Post, Render, Req, Body, ValidationPipe, BadRequestException } from '@nestjs/common';
import { AppService } from './app.service';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { UfwService } from './ufw/ufw.service';

@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly configService: ConfigService,
    private readonly ufwService: UfwService,
  ) {}

  @Get()
  @Render('index')
  getMainPage(@Req() req: Request) {
    const rpcUrl = this.appService.getRpcUrl();
    const geyserUrl = this.appService.getGeyserUrl();
    
    const isAuthenticated = !!req.session?.isAuthenticated;

    return {
      pageTitle: 'Diver\'s Solana RPC Node',
      welcomeMessage: "Welcome to Diver\'s Solana RPC node!",
      rpcUrl: rpcUrl,
      geyserUrl: geyserUrl,
      rpcPort: this.configService.get<string>('RPC_PORT'),
      geyserPort: this.configService.get<string>('GEYSER_PORT'),
      currentIp: this.appService.getPublicIp(),
      isAuthenticated: isAuthenticated,
    };
  }

  @Post('check-ip')
  async checkIpStatus(@Body('ip') ipAddress: string) {
    if (!ipAddress || !/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ipAddress)) {
      throw new BadRequestException('Invalid IP address format provided.');
    }
    try {
      const result = await this.ufwService.checkIpAccess(ipAddress);
      return result;
    } catch (error) {
      throw error;
    }
  }
}
