import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class AuthGuard implements CanActivate {
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest();
    if (!request.session || !request.session.isAuthenticated) {
      // You might want to redirect to login or throw a different error
      // For API-like behavior, UnauthorizedException is common.
      // For web pages, you might redirect.
      // throw new UnauthorizedException('User is not authenticated');
      
      // For this app, let's redirect to the login page
      const response = context.switchToHttp().getResponse();
      response.redirect('/auth/login');
      return false; // Important to return false after redirecting
    }
    return true;
  }
} 