import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Request,
  UseGuards,
  HttpStatus,
  HttpCode,
} from "@nestjs/common";
import { LocalAuthGuard } from "./local-auth.guard";
import { AuthService } from "./auth.service";
import { JwtAuthGuard } from "./jwt-auth.guard";
import { CreateUserDto } from "src/users/dto/create-user.dto";
import { LoginUserDto } from "src/users/dto/login-user.dto";

@Controller("auth")
export class AuthController {
  constructor(private authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post("login")
  async login(@Body() userDto: any) {
    return this.authService.login(userDto.username, userDto.password);
  }

  // @HttpCode(HttpStatus.OK)
  // @Post("login2")
  // signIn(@Body() signInDto: Record<string, any>) {
  //   return this.authService.signIn(signInDto.username, signInDto.password);
  // }

  @Post("registration")
  registration(@Body() userDto: CreateUserDto) {
    return this.authService.registration(userDto);
  }

  @UseGuards(JwtAuthGuard)
  @Get("profile")
  getProfile(@Request() req: any) {
    return {
      id: req.user._id,
      username: req.user.username,
      createdAt: req.user.createdAt,
      updatedAt: req.user.updatedAt,
      token: this.authService.login(req.user.username, req.user.password),
    };
  }
}
