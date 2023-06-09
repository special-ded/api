import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
import { Exclude } from "class-transformer";

export type UserDocument = User & Document;

@Schema({
  timestamps: true,
  id: true,
  versionKey: false,
  toJSON: {
    transform: function(doc, ret) {
      ret.id = ret._id;
      delete ret._id;
    },
    virtuals: true,
    getters: true
  },
})
export class User {

  @Prop({
    required: true,
    default: uuidv4,
  })
  _id: uuidv4;

  @Prop({
    required: true,
    unique: true,
    dropDups: true
  })
  username: string;

  @Prop({
    required: true
  })
  @Exclude()
  password: string;
}

export const UserSchema = SchemaFactory.createForClass(User);
