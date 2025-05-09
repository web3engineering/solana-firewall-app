import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(private readonly configService: ConfigService) {}

  async validateUser(password: string): Promise<boolean> {
    const actualPassword = this.configService.get<string>('PASS');
    return password === actualPassword;
  }
}
