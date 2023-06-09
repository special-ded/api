import { Controller, Get, Post, Req, Request, UseGuards } from "@nestjs/common";
import { LocalAuthGuard } from './local-auth.guard';
import { AuthService } from "./auth.service";
import { JwtAuthGuard } from "./jwt-auth.guard";

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService
  ) {
  }

  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Req() { user }: any) {
    return this.authService.login(user);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req: any) {
    return {
      id: req.user._id,
      username: req.user.username,
      createdAt: req.user.createdAt,
      updatedAt: req.user.updatedAt,
    };
  }
}
