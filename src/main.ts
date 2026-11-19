import 'reflect-metadata';
import { Logger, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { json } from 'express';

import { AppModule } from './app.module';
import { ErrorFirmadorFilter } from './infrastructure/rest/error-firmador.filter';

async function bootstrap() {
  // Fuera de Docker las variables vienen de .env; dentro, de env_file.
  try {
    process.loadEnvFile();
  } catch {
    // sin .env: se usan las variables del entorno
  }

  // Se desactiva el body parser por defecto para poder subir el limite: un
  // comprobante con muchos detalles supera los 100kb que trae Nest de fabrica.
  const app = await NestFactory.create(AppModule.registrar(process.env), { bodyParser: false });
  app.enableShutdownHooks();

  app.use(json({ limit: process.env.SIGNER_MAX_BODY ?? '10mb' }));
  app.useGlobalPipes(
    new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }),
  );
  app.useGlobalFilters(new ErrorFirmadorFilter());

  const puerto = Number(process.env.PORT ?? 3001);
  await app.listen(puerto, '0.0.0.0');

  new Logger('Bootstrap').log(`signer-service escuchando en :${puerto}`);
}

void bootstrap();
