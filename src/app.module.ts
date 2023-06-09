import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ProductsModule } from './products/products.module';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { OrderModule } from './order/order.module';
import { ConfigModule } from "@nestjs/config";
import * as process from "process";

@Module({
  imports: [
    ProductsModule,
    ProductsModule,
    UsersModule,
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.development.env',
      ignoreEnvFile: process.env.NODE_ENV === 'prod',
    }),
    MongooseModule.forRoot(`mongodb+srv://${
      process.env.DB_USER
    }:${
      process.env.DB_PASSWORD
    }@${
      process.env.DB_CLUSTER
    }.${
      process.env.DB_SERVICE_HASH
    }.mongodb.net/products?retryWrites=true&w=majority`,{
      autoIndex: true,
    }),
    AuthModule,
    OrderModule,
  ],
  controllers: [AppController],
  providers: [AppService]
})
export class AppModule {
}
