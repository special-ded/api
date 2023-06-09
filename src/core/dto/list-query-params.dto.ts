import {
  IsDefined,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  Length,
  Max,
  Min
} from "class-validator";
import { Type } from "class-transformer";

export class ListQueryParamsDto {
  @Min(1)
  @Max(200)
  @IsInt()
  @IsDefined()
  @IsNotEmpty()
  @IsOptional()
  @Type(() => Number)
  limit: number;

  @Length(3, 255)
  @IsString()
  @IsDefined()
  @IsNotEmpty()
  @IsOptional()
  sort: string;

  @Min(1)
  @Max(200)
  @IsInt()
  @IsDefined()
  @IsNotEmpty()
  @IsOptional()
  @Type(() => Number)
  page: number;

  @IsDefined()
  @IsNotEmpty()
  @IsOptional()
  filter: string | string[];
}