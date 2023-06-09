import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
import * as mongoose from 'mongoose';

export type ProductDocument = Product & Document;

@Schema({
  timestamps: true,
  id: true,
  versionKey: false,
  toJSON: {
    transform: function(doc, ret) {
      ret.id = ret._id;
      delete ret._id;
    },
  },
})
export class Product {

  @Prop({
    required: true,
    default: uuidv4,
  })
  _id: uuidv4;

  @Prop({
    required: true
  })
  name: string;

  @Prop({
    required: true
  })
  price: number;

  @Prop({
    required: true
  })
  description: string;

  @Prop({
    required: true
  })
  author: string;

  @Prop({type: mongoose.Schema.Types.Mixed})
  extraInfo: object;
}

export const ProductSchema = SchemaFactory.createForClass(Product);
