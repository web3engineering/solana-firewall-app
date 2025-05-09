import { Controller, Post, Body, Session, Res, Get, HttpStatus, UseGuards, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Response, Request } from 'express'; // Import Response and Request

declare module 'express-session' {
  interface SessionData {
    isAuthenticated?: boolean;
  }
}

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('login')
  getLoginPage(@Res() res: Response) {
    // Simple HTML form for login
    // In a real app, you'd use a template or a frontend framework
    res.send(`
      <html>
        <head><title>Login</title></head>
        <body>
          <h2>Login</h2>
          <form action="/auth/login" method="post">
            <div>
              <label for="password">Password:</label>
              <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
          </form>
        </body>
      </html>
    `);
  }

  @Post('login')
  async login(
    @Body('password') passwordBody: string, // Assuming password comes directly in body
    @Session() session: Record<string, any>,
    @Res({ passthrough: true }) res: Response,
  ) {
    const isValid = await this.authService.validateUser(passwordBody);
    if (isValid) {
      session.isAuthenticated = true;
      // Redirect to /rules on successful login
      return res.redirect('/rules');
    } else {
      // Send an unauthorized status and potentially an error message or redirect to login with error
      return res.status(HttpStatus.UNAUTHORIZED).redirect('/auth/login?error=1');
    }
  }

  @Post('logout')
  logout(@Session() session: Record<string, any>, @Res({ passthrough: true }) res: Response) {
    session.isAuthenticated = false;
    // session.destroy(); // Optional: completely destroy session
    return res.redirect('/auth/login');
  }

  @Get('status')
  status(@Session() session: Record<string, any>) {
    return { isAuthenticated: !!session.isAuthenticated };
  }
}
