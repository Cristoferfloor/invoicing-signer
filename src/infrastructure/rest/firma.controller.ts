import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
} from '@nestjs/common';

import {
  FIRMAR_DOCUMENTO_USE_CASE,
  FirmarDocumentoUseCase,
} from '../../domain/ports/firmar-documento.use-case';
import { FirmarRequestDto, FirmarResponseDto } from './dto/firmar.dto';

@Controller('v1/firmas')
export class FirmaController {
  constructor(
    @Inject(FIRMAR_DOCUMENTO_USE_CASE)
    private readonly firmarDocumento: FirmarDocumentoUseCase,
  ) {}

  @Post()
  @HttpCode(HttpStatus.OK)
  async firmar(@Body() peticion: FirmarRequestDto): Promise<FirmarResponseDto> {
    const resultado = await this.firmarDocumento.firmar({
      documentoId: peticion.documentoId,
      xmlBase64: peticion.xmlBase64,
      certificadoRef: peticion.certificadoRef,
    });

    return { estado: 'FIRMADO', ...resultado };
  }
}
