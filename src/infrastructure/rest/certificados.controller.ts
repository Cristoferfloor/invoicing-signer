import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Param,
  Post,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { IsNotEmpty, IsString, Matches, MaxLength } from 'class-validator';

import {
  REGISTRAR_CERTIFICADO_USE_CASE,
  RegistrarCertificadoUseCase,
} from '../../domain/ports/registrar-certificado.use-case';
import { esRucValido } from '../../domain/certificado-empresa';
import { TokenAdminGuard } from './token-admin.guard';

const RUC = /^\d{10}00[1-9]$/;

export class RegistrarCertificadoDto {
  @Matches(RUC, { message: 'empresaRuc debe ser un RUC de 13 digitos.' })
  empresaRuc!: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(256)
  clave!: string;
}

@Controller('v1/certificados')
@UseGuards(TokenAdminGuard)
export class CertificadosController {
  constructor(
    @Inject(REGISTRAR_CERTIFICADO_USE_CASE)
    private readonly registro: RegistrarCertificadoUseCase,
  ) {}

  // multipart/form-data: empresaRuc, clave y archivo (.p12 o .pfx).
  @Post()
  @HttpCode(HttpStatus.CREATED)
  @UseInterceptors(FileInterceptor('archivo', { limits: { fileSize: 64 * 1024, files: 1 } }))
  async registrar(
    @Body() peticion: RegistrarCertificadoDto,
    @UploadedFile() archivo: Express.Multer.File | undefined,
  ) {
    if (!archivo) throw new BadRequestException('Falta el archivo del certificado (campo "archivo").');

    const resultado = await this.registro.registrar({
      empresaRuc: peticion.empresaRuc,
      archivo: archivo.buffer,
      clave: peticion.clave,
    });

    return {
      estado: resultado.yaExistia ? 'YA_REGISTRADO' : 'REGISTRADO',
      certificado: resultado.certificado,
      reemplazados: resultado.reemplazados,
    };
  }

  @Get(':empresaRuc')
  async listar(@Param('empresaRuc') empresaRuc: string) {
    if (!esRucValido(empresaRuc)) throw new BadRequestException('RUC invalido.');
    return { empresaRuc, certificados: await this.registro.listar(empresaRuc) };
  }
}
