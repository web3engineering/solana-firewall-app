import { Controller, Get, Post, Body, Res, UseGuards, Render, Param, BadRequestException } from '@nestjs/common';
import { UfwService } from './ufw.service';
import { AuthGuard } from '../auth/auth.guard'; // Adjust path as necessary
import { Response } from 'express';

@Controller('rules')
@UseGuards(AuthGuard) // Protect all routes in this controller
export class UfwController {
  constructor(private readonly ufwService: UfwService) {}

  @Get()
  @Render('rules/index') // Will render views/rules/index.hbs
  async getRulesPage() {
    const rules = await this.ufwService.getRules();
    return { rules: rules, pageTitle: 'UFW Rules Management' };
  }

  @Post('add')
  async addRule(
    @Body('ip') ip: string, 
    @Res() res: Response
  ) {
    // Basic IP validation (NestJS ParseIPPipe can be more robust or use class-validator)
    if (!ip || !/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip)) {
        // Ideally, provide feedback to the user on the page
        // For now, redirecting with an error query param or throwing an error
        // return res.redirect('/rules?error=Invalid IP address');
        throw new BadRequestException('Invalid IP address format.');
    }
    await this.ufwService.addRulesForIp(ip);
    return res.redirect('/rules');
  }

  // Using a POST request for deletion is generally better than GET with params
  // if the action has side effects, which this does.
  @Post('delete') 
  async deleteRule(
    @Body('ip') ip: string, 
    @Res() res: Response
  ) {
    if (!ip || !/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip)) {
        throw new BadRequestException('Invalid IP address format for deletion.');
    }
    await this.ufwService.deleteRulesForIp(ip);
    return res.redirect('/rules');
  }
}
