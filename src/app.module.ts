import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { UfwModule } from './ufw/ufw.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, // Make ConfigModule available globally
      envFilePath: '.env', // Specify the .env file path
    }),
    AuthModule,
    UfwModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
