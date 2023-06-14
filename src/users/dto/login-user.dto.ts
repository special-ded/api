import { IsDefined, IsNotEmpty, IsString, Length } from "class-validator";

export class LoginUserDto {
  @IsDefined()
  @IsString()
  @IsNotEmpty()
  readonly username: string;

  @Length(3, 60, { message: "must be from 3 to 60 letters" })
  @IsDefined()
  @IsString()
  @IsNotEmpty({ message: "must not be empty" })
  readonly password: string;
}
