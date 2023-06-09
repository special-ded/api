import {
  Body,
  Controller,
  Delete,
  Get,
  Header,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Put,
  Query,
  UseGuards,
  ValidationPipe,
} from "@nestjs/common";
import { UsersService } from "./users.service";
import { CreateUserDto } from "./dto/create-user.dto";
import { UpdateUserDto } from "./dto/update-user.dto";
import { User } from "./shemas/users.schema";
import { JwtAuthGuard } from "../auth/jwt-auth.guard";
import { HttpException } from "@nestjs/common/exceptions/http.exception";
import { ListQueryParamsDto } from "../core/dto/list-query-params.dto";
// import { Role } from "src/auth/role-auth.decorator";

@UseGuards(JwtAuthGuard)
@Controller("users")
export class UsersController {
  constructor(private usersService: UsersService) {}

  // @Role("ADMIN")
  @Get()
  @HttpCode(HttpStatus.OK)
  public getAll(
    @Query(
      new ValidationPipe({
        transform: true,
        transformOptions: {
          enableImplicitConversion: false,
        },
        forbidNonWhitelisted: true,
      })
    )
    query: ListQueryParamsDto
  ): Promise<User[]> {
    return this.usersService.getAll(query);
  }

  // @Role("ADMIN")
  @Get(":id")
  public getOne(@Param("id") id: string): Promise<User> {
    return this.usersService.getById(id);
  }

  // @Role("ADMIN")
  @Post()
  @HttpCode(HttpStatus.CREATED)
  @Header("Ololo-Header", "777")
  public create(@Body() body: CreateUserDto): Promise<User | HttpException> {
    return this.usersService.create(body);
  }

  // @Role("ADMIN")
  @Delete(":id")
  @HttpCode(HttpStatus.OK)
  public remove(@Param("id") id: string): Promise<User> {
    return this.usersService.remove(id);
  }

  // TODO add params validation
  /*
  shared
   export class FindOneParams {
     @IsNumberString()
     id: number;
   }

   @Param() params: FindOneParams,
  * */

  // @Role("ADMIN")
  @Put(":id")
  @HttpCode(HttpStatus.OK)
  public update(
    @Param("id") id: string,
    @Body() body: UpdateUserDto
  ): Promise<User> {
    return this.usersService.update(id, body);
  }
}
