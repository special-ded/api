import {
  IsDefined,
  IsNotEmpty, IsNotEmptyObject,
  IsNumber,
  IsObject,
  IsOptional,
  IsPositive,
  IsString,
  Length,
  Max,
  Min
} from "class-validator";

export class CreateProductDto {
  @Length(3, 255)
  @IsString()
  @IsDefined()
  @IsNotEmpty()
  readonly name: string;

  // @Length(3, 255)
  // @IsString()
  // @IsDefined()
  // @IsNotEmpty()
  // readonly author: string;

  @Length(15, 1000)
  @IsString()
  @IsDefined()
  @IsNotEmpty()
  readonly description: string;

  @IsNumber()
  @IsDefined()
  @IsNotEmpty()
  @IsPositive()
  @Min(1)
  @Max(999999)
  readonly price: number;

  @IsOptional()
  @IsObject()
  @IsNotEmptyObject()
  readonly extraInfo: any;
}