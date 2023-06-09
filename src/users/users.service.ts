import {
  ConflictException,
  HttpStatus,
  Injectable,
  InternalServerErrorException,
} from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { User, UserDocument } from "./shemas/users.schema";
import { UpdateUserDto } from "./dto/update-user.dto";
import { CreateUserDto } from "./dto/create-user.dto";
import { HttpException } from "@nestjs/common/exceptions/http.exception";
import { BaseControllerService } from "../core/base/base-controller.service";
import { ListQueryParamsDto } from "../core/dto/list-query-params.dto";
import { use } from "passport";

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private model: Model<UserDocument>) {}

  public async getAll(query: ListQueryParamsDto): Promise<User[]> {
    return BaseControllerService.getAll<User>(this.model, query);
  }

  public async findOne(username: string): Promise<User | undefined> {
    return this.model.findOne({ username }).exec();
  }

  public async getById(id: string): Promise<User> {
    return this.model.findById(id);
  }

  public async create(body: CreateUserDto): Promise<User | HttpException> {
    try {
      return await new this.model({
        ...body,
        password: await BaseControllerService.hashPWD(body.password),
      }).save();
    } catch ({ code }) {
      if (code === 11000) {
        throw new ConflictException("User with such name already exists");
      }

      throw new InternalServerErrorException();
    }
  }

  public async remove(id: string): Promise<User> {
    throw new HttpException("Users cannot be deleted", HttpStatus.FORBIDDEN);
  }

  public async update(id: string, body: UpdateUserDto): Promise<User> {
    const query = BaseControllerService.validateNoEntity(
      this.model.findByIdAndUpdate(
        id,
        {
          ...body,
          password: await BaseControllerService.hashPWD(body.password),
        },
        { new: true, runValidators: true }
      ),
      "User"
    );

    return await BaseControllerService.validateAdmin(id, this.model, query);
  }
}
