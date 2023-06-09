import { Injectable } from "@nestjs/common";
import { CreateProductDto } from './dto/create-product.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Product, ProductDocument } from './shemas/products.schema';
import { Model } from "mongoose";
import { UpdateProductDto } from './dto/update-product.dto';
import { ListQueryParamsDto } from "../core/dto/list-query-params.dto";
import { BaseControllerService } from "../core/base/base-controller.service";

@Injectable()
export class ProductsService {
  constructor(
    @InjectModel(Product.name) private model: Model<ProductDocument>
  ) {}

  public async getAll(
    query: ListQueryParamsDto
  ): Promise<{ productsByQuery: Product[], allProductsCount: number }> {
    return {
      allProductsCount: await this.model.countDocuments(),
      productsByQuery: await BaseControllerService.getAll<Product>(this.model, query)
    };
  }

  public async getById(id: string): Promise<Product> {
    return this.model.findById(id);
  }

  public async create(body: CreateProductDto, req: any): Promise<Product> {
    return new this.model({
      ...body,
      author: req.user.username
    }).save();
  }

  public async remove(id: string): Promise<Product> {
    return this.model.findByIdAndRemove(id);
  }

  public async update(
    id: string,
    body: UpdateProductDto
  ): Promise<Product> {
    return this.model.findByIdAndUpdate(
      id,
      body,
      { new: true }
    );
  }
}
