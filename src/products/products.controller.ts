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
  Put, Query, Request, UseGuards, ValidationPipe, Res
} from "@nestjs/common";
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { ProductsService } from './products.service';
import { Product } from './shemas/products.schema';
import { ListQueryParamsDto } from "../core/dto/list-query-params.dto";
import { JwtAuthGuard } from "../auth/jwt-auth.guard";
import { Response } from 'express';

@Controller('products')
export class ProductsController {
  constructor(
    private productsService: ProductsService
  ) {
  }

  @Get()
  @HttpCode(HttpStatus.OK)
  public async getAll(
    @Query(new ValidationPipe({
      transform: true,
      transformOptions: {
        enableImplicitConversion: false
      },
      forbidNonWhitelisted: true
    })) query: ListQueryParamsDto,
    @Res() res: Response
  ): Promise<Response> {
    const { allProductsCount, productsByQuery } = await this.productsService.getAll(query || {} as any);

    res.header( 'all-products', allProductsCount.toString());
    res.json(productsByQuery);
    return res;
  }

  @Get(':id')
  public getOne(@Param('id') id: string): Promise<Product> {
    return this.productsService.getById(id);
  }

  @UseGuards(JwtAuthGuard)
  @Post()
  @HttpCode(HttpStatus.CREATED)
  @Header('Ololo-Header', '777')
  public create(
    @Body() body: CreateProductDto,
    @Request() req: any
  ): Promise<Product> {
    return this.productsService.create(body, req);
  }

  @UseGuards(JwtAuthGuard)
  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  public remove(@Param('id') id: string): Promise<Product> {
    return this.productsService.remove(id);
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

  @UseGuards(JwtAuthGuard)
  @Put(':id')
  @HttpCode(HttpStatus.OK)
  public update(
    @Param('id') id: string,
    @Body() body: UpdateProductDto,
  ): Promise<Product> {
    return this.productsService.update(id, body);
  }
}
