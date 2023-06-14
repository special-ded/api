import {
  HttpException,
  UnauthorizedException,
  HttpStatus,
  Injectable,
} from "@nestjs/common";
import { UsersService } from "../users/users.service";
import { JwtService } from "@nestjs/jwt";
import * as bcrypt from "bcrypt";
import { CreateUserDto } from "src/users/dto/create-user.dto";
import { LoginUserDto } from "src/users/dto/login-user.dto";

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService
  ) {}

  // async validateUser(username: string, pwd: string): Promise<any> {
  //   const user = await this.usersService.findOne(username);
  //   const pwdMatch: boolean =
  //     user && (await this.verifyPassword(pwd, user.password));

  //   if (pwdMatch) {
  //     const { password, ...result } = user;

  //     return result;
  //   }
  //   return null;
  // }

  // async login(user: any) {
  //   return {
  //     access_token: this.jwtService.sign(user._doc),
  //   };
  // }

  async login(dto: LoginUserDto) {
    const user = await this.validateUser(dto);
    return this.generateToken(user);
  }
  private async validateUser(dto: LoginUserDto) {
    const user = await this.usersService.findOne(dto.username);
    if (!user) {
      throw new UnauthorizedException({
        message: "Incorrect password or email",
      });
    }
    const passwordEquals = await bcrypt.compare(dto.password, user.password);

    if (user && passwordEquals) {
      return user;
    }
    throw new UnauthorizedException({
      message: "Incorrect password or email",
    });
  }

  async registration(dto: CreateUserDto) {
    const regUser = await this.usersService.findOne(dto.username);
    if (regUser) {
      throw new HttpException("User already exists", HttpStatus.BAD_REQUEST);
    }
    const hashPassword = await bcrypt.hash(dto.password, 5);
    const user = await this.usersService.create({
      ...dto,
      password: hashPassword,
    });

    return this.generateToken(user);
  }

  public async verifyPassword(
    textPwd: string,
    hashedPwd: string
  ): Promise<boolean> {
    return bcrypt.compare(textPwd, hashedPwd);
  }

  private async generateToken(user: any) {
    const payload = {
      username: user.username,
      email: user.email,
      id: user._id,
      role: user.role,
    };
    return {
      token: this.jwtService.sign(payload),
    };
  }
}
