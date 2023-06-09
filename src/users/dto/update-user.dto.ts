import { PartialType } from "@nestjs/mapped-types";
import { CreateUserDto } from "./create-user.dto";
import { IsDefined, IsNotEmpty, IsString, Length } from "class-validator";

export class UpdateUserDto {
  @Length(3, 255)
  @IsString()
  @IsDefined()
  @IsNotEmpty()
  readonly password: string;
}