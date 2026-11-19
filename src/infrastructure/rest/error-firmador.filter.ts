import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Response } from 'express';

import { ErrorFirmador } from '../../domain/errors/firmador.errors';
import { ErrorFirmaDto } from './dto/firmar.dto';

const ESTADO_HTTP: Record<string, HttpStatus> = {
  CERTIFICADO_NO_ENCONTRADO: HttpStatus.NOT_FOUND,
  CERTIFICADO_INVALIDO: HttpStatus.UNPROCESSABLE_ENTITY,
  CERTIFICADO_VENCIDO: HttpStatus.UNPROCESSABLE_ENTITY,
  CERTIFICADO_DE_OTRA_EMPRESA: HttpStatus.UNPROCESSABLE_ENTITY,
  XML_INVALIDO: HttpStatus.BAD_REQUEST,
  FIRMA_FALLIDA: HttpStatus.INTERNAL_SERVER_ERROR,
};

@Catch(ErrorFirmador)
export class ErrorFirmadorFilter implements ExceptionFilter<ErrorFirmador> {
  private readonly logger = new Logger(ErrorFirmadorFilter.name);

  catch(excepcion: ErrorFirmador, host: ArgumentsHost): void {
    const respuesta = host.switchToHttp().getResponse<Response>();
    const estado =
      ESTADO_HTTP[excepcion.codigo] ?? HttpStatus.INTERNAL_SERVER_ERROR;

    this.logger.warn(
      JSON.stringify({
        evento: 'firma_rechazada',
        error: excepcion.codigo,
        mensaje: excepcion.message,
      }),
    );

    const cuerpo: ErrorFirmaDto = {
      estado: 'RECHAZADO',
      error: excepcion.codigo,
      mensaje: excepcion.message,
    };

    respuesta.status(estado).json(cuerpo);
  }
}
