import { IsBase64, IsNotEmpty, IsString, Matches, MaxLength } from 'class-validator';

export class FirmarRequestDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  documentoId!: string;

  @IsString()
  @IsNotEmpty()
  @IsBase64()
  xmlBase64!: string;

  @IsString()
  @Matches(/^[A-Za-z0-9_-]{1,64}$/, {
    message: 'certificadoRef solo admite letras, numeros, guion y guion bajo.',
  })
  certificadoRef!: string;
}

export class FirmarResponseDto {
  estado!: 'FIRMADO';
  documentoId!: string;
  xmlFirmadoBase64!: string;
  huella!: string;
  firmadoEn!: string;
}

export class ErrorFirmaDto {
  estado!: 'RECHAZADO';
  error!: string;
  mensaje!: string;
}
