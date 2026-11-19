import { Controller, Get } from '@nestjs/common';

@Controller('salud')
export class SaludController {
  @Get()
  estado() {
    return {
      estado: 'ok',
      servicio: 'signer-service',
      version: process.env.npm_package_version ?? '0.1.0',
    };
  }
}
