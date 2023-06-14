import { IsDefined, IsNotEmpty, IsString, Length } from "class-validator";

export class CreateUserDto {
  @Length(3, 255, { message: "must be from 3 to 60 letters" })
  @IsString()
  @IsDefined()
  @IsNotEmpty({ message: "must not be empty" })
  readonly username: string;

  @Length(3, 255, { message: "must be from 3 to 60 letters" })
  @IsString()
  @IsDefined()
  @IsNotEmpty({ message: "must not be empty" })
  readonly password: string;

  @Length(3, 25)
  @IsString()
  @IsDefined()
  @IsNotEmpty()
  readonly role: string;
}
