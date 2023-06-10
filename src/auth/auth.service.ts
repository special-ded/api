import { Injectable } from "@nestjs/common";
import { UsersService } from "../users/users.service";
import { JwtService } from "@nestjs/jwt";
import * as bcrypt from "bcrypt";

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService
  ) {}

  async validateUser(username: string, pwd: string): Promise<any> {
    const user = await this.usersService.findOne(username);
    const pwdMatch: boolean =
      user && (await this.verifyPassword(pwd, user.password));

    if (pwdMatch) {
      const { password, ...result } = user;

      return result;
    }
    return null;
  }

  async login(user: any) {
    return {
      access_token: this.jwtService.sign(user._doc),
    };
  }

  public async verifyPassword(
    textPwd: string,
    hashedPwd: string
  ): Promise<boolean> {
    return bcrypt.compare(textPwd, hashedPwd);
  }
}
