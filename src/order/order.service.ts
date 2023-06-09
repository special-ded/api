import { Injectable } from '@nestjs/common';
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { Order, OrderDocument } from "./schemas/order.schema";
import { CreateOrderDto } from "./dto/create-order.dto";
import { UpdateOrderDto } from "./dto/update-order.dto";
import { ListQueryParamsDto } from "../core/dto/list-query-params.dto";
import { BaseControllerService } from "../core/base/base-controller.service";

@Injectable()
export class OrderService {
  constructor(
    @InjectModel(Order.name) private model: Model<OrderDocument>
  ) {}

  public async getAll(
    query: ListQueryParamsDto
  ): Promise<Order[]> {
    return BaseControllerService.getAll<Order>(this.model, query);
  }

  public async getById(id: string): Promise<Order> {
    return this.model.findById(id);
  }

  public async create(body: CreateOrderDto): Promise<Order> {
    return new this.model(body).save();
  }

  public async remove(id: string): Promise<Order> {
    return this.model.findByIdAndRemove(id);
  }

  public async update(
    id: string,
    body: UpdateOrderDto
  ): Promise<Order> {
    return this.model.findByIdAndUpdate(
      id,
      body,
      { new: true }
    );
  }
}
