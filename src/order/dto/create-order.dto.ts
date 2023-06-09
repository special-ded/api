import { OrderProduct } from "../schemas/order.schema";
import {
  ArrayMaxSize,
  ArrayMinSize,
  ArrayNotEmpty,
  ArrayUnique,
  IsArray,
  IsDefined, IsMobilePhone,
  IsNotEmpty, IsOptional, IsPhoneNumber, IsString, Length, ValidateNested
} from "class-validator";

export class CreateOrderDto {
  @Length(3, 255)
  @IsString()
  @IsDefined()
  @IsNotEmpty()
  readonly name: string;

  @IsDefined()
  @IsNotEmpty()
  @IsPhoneNumber()
  @IsMobilePhone()
  readonly phone: string;

  @ArrayMinSize(1)
  @ArrayMaxSize(10)
  @ArrayNotEmpty()
  @IsArray()
  @IsDefined()
  @IsNotEmpty()
  @ArrayUnique((o: OrderProduct): string => o.id)
  // TODO @ValidateNested({each: true})
  // new ParseArrayPipe({ items: CreateUserDto })
  readonly products: OrderProduct[];


  @IsString()
  @IsOptional()
  readonly message: string;
}