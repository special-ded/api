import {
  IsDefined,
  IsNotEmpty,
  IsNotEmptyObject,
  IsNumber,
  IsObject,
  IsOptional,
  IsPositive,
  IsString,
  Length,
  Max,
  Min,
} from "class-validator";

export class CreateUserDto {
  @Length(3, 255)
  @IsString()
  @IsDefined()
  @IsNotEmpty()
  readonly username: string;

  @Length(3, 255)
  @IsString()
  @IsDefined()
  @IsNotEmpty()
  readonly password: string;

  @Length(3, 25)
  @IsString()
  @IsDefined()
  @IsNotEmpty()
  readonly role: string;
}
