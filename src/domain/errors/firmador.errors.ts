export abstract class ErrorFirmador extends Error {
  abstract readonly codigo: string;

  constructor(mensaje: string) {
    super(mensaje);
    this.name = new.target.name;
  }
}

export class CertificadoNoEncontradoError extends ErrorFirmador {
  readonly codigo = 'CERTIFICADO_NO_ENCONTRADO';
}

export class CertificadoInvalidoError extends ErrorFirmador {
  readonly codigo = 'CERTIFICADO_INVALIDO';
}

export class CertificadoVencidoError extends ErrorFirmador {
  readonly codigo = 'CERTIFICADO_VENCIDO';
}

export class CertificadoDeOtraEmpresaError extends ErrorFirmador {
  readonly codigo = 'CERTIFICADO_DE_OTRA_EMPRESA';
}

export class XmlInvalidoError extends ErrorFirmador {
  readonly codigo = 'XML_INVALIDO';
}

export class FirmaFallidaError extends ErrorFirmador {
  readonly codigo = 'FIRMA_FALLIDA';
}
