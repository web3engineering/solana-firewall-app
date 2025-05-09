import { Module } from '@nestjs/common';
import { UfwController } from './ufw.controller';
import { UfwService } from './ufw.service';

@Module({
  controllers: [UfwController],
  providers: [UfwService],
  exports: [UfwService]
})
export class UfwModule {}
