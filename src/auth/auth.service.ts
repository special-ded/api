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
    if (!user) {
      throw new UnauthorizedException({
        message: `Incorrect username + ${username},pass: ${pwd},`,
      });
    }
    const hash = await bcrypt.hash("123456", 5);
    const compare2 = await bcrypt.compare("123456", hash);
    const compare = await bcrypt.compare(pwd, user?.password);
    if (!compare) {
      throw new UnauthorizedException({
        message: `Incorrect password or email2 + ${user?.password}, 
        pass: ${pwd}, COMPARE: ${compare}, COMPARE2: ${compare2}`,
      });
    }

    const { password, ...result } = user;
    return user;
  }

  async login(username: string, pass: string): Promise<any> {
    const user = await this.validateUser(username, pass);
    return this.generateToken(user);
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
    if (!bcrypt.compare(textPwd, hashedPwd)) {
      throw new UnauthorizedException({
        message: `Incorrect password or email1 + ${bcrypt.compare(
          textPwd,
          hashedPwd
        )},pass: ${textPwd}`,
      });
    }
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
