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

  async validateUser(username: string, pwd: string): Promise<any> {
    const user = await this.usersService.findOne(username);
    const pwdMatch: boolean =
      user && (await this.verifyPassword(pwd, user.password));

    if (pwdMatch) {
      const { password, ...result } = user;

      return user;
    }
    return null;
  }

  // async login(user: any) {
  //   return {
  //     access_token: this.jwtService.sign(user._doc),
  //   };
  // }

  async signIn(username: string, pass: string): Promise<any> {
    const user = await this.usersService.findOne(username);
    if (user?.password !== pass) {
      throw new UnauthorizedException({
        message: `Incorrect password or email1 + ${username} ${pass}`,
      });
    }
    const { password, ...result } = user;
    // TODO: Generate a JWT and return it here
    // instead of the user object
    return result;
  }

  async login(username: string, pass: string): Promise<any> {
    const user = await this.validateUser(username, pass);
    return this.generateToken(user);
  }

  // private async validateUser(username: string, pass: string) {
  //   const user = await this.usersService.findOne(username);
  //   if (!user) {
  //     throw new UnauthorizedException({
  //       message: `Incorrect password or email1 + ${username},pass: ${pass}`,
  //     });
  //   }
  //   const passwordEquals = await bcrypt.compare(pass, user.password);

  //   if (user && passwordEquals) {
  //     return user;
  //   }
  //   throw new UnauthorizedException({
  //     message: `Incorrect password or email2 + ${user} PASS:${user.password} EQUAL: ${passwordEquals}`,
  //   });
  // }

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
