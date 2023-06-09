import { Injectable } from "@nestjs/common";

@Injectable()
export class AppService {
  getHello(): string {
    return `<h1>Ivan Draganov API - v=1.2</h1>`;
  }
}
