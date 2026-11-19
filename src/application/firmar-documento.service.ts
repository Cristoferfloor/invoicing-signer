import { Inject, Injectable, Logger } from '@nestjs/common';
import { createHash } from 'node:crypto';

import {
  FIRMAR_DOCUMENTO_USE_CASE,
  FirmarDocumentoUseCase,
} from '../domain/ports/firmar-documento.use-case';
import {
  ALMACEN_CERTIFICADOS_PORT,
  AlmacenCertificadosPort,
} from '../domain/ports/almacen-certificados.port';
import {
  FIRMADOR_XML_PORT,
  FirmadorXmlPort,
} from '../domain/ports/firmador-xml.port';
import { SolicitudFirma } from '../domain/model/solicitud-firma.model';
import { ResultadoFirma } from '../domain/model/resultado-firma.model';
import { CertificadoDigital } from '../domain/model/certificado-digital.model';
import {
  CertificadoVencidoError,
  XmlInvalidoError,
} from '../domain/errors/firmador.errors';

@Injectable()
export class FirmarDocumentoService implements FirmarDocumentoUseCase {
  private readonly logger = new Logger(FirmarDocumentoService.name);

  constructor(
    @Inject(ALMACEN_CERTIFICADOS_PORT)
    private readonly certificados: AlmacenCertificadosPort,
    @Inject(FIRMADOR_XML_PORT)
    private readonly firmadorXml: FirmadorXmlPort,
  ) {}

  async firmar(solicitud: SolicitudFirma): Promise<ResultadoFirma> {
    const inicio = Date.now();
    const xml = this.decodificarXml(solicitud.xmlBase64);
    const certificado = await this.certificados.obtener(solicitud.certificadoRef);

    this.verificarVigencia(certificado);

    const xmlFirmado = await this.firmadorXml.firmar(xml, certificado);
    const huella = this.calcularHuella(xmlFirmado);

    this.logger.log(
      JSON.stringify({
        evento: 'documento_firmado',
        documentoId: solicitud.documentoId,
        certificadoRef: certificado.ref,
        huella,
        duracionMs: Date.now() - inicio,
      }),
    );

    return {
      documentoId: solicitud.documentoId,
      xmlFirmadoBase64: Buffer.from(xmlFirmado, 'utf8').toString('base64'),
      huella,
      firmadoEn: new Date().toISOString(),
    };
  }

  private decodificarXml(xmlBase64: string): string {
    const xml = Buffer.from(xmlBase64, 'base64').toString('utf8');

    if (!xml.trimStart().startsWith('<')) {
      throw new XmlInvalidoError(
        'El contenido decodificado desde xmlBase64 no es XML.',
      );
    }

    return xml;
  }

  // Firmar con un certificado vencido produce un comprobante que el SRI
  // rechaza; se corta aqui para que el error sea explicito y no un rechazo
  // opaco despues del envio.
  private verificarVigencia(certificado: CertificadoDigital): void {
    const ahora = new Date();

    if (ahora > certificado.validoHasta) {
      throw new CertificadoVencidoError(
        `El certificado ${certificado.ref} vencio el ${certificado.validoHasta.toISOString()}.`,
      );
    }

    if (ahora < certificado.validoDesde) {
      throw new CertificadoVencidoError(
        `El certificado ${certificado.ref} recien es valido desde el ${certificado.validoDesde.toISOString()}.`,
      );
    }
  }

  private calcularHuella(xmlFirmado: string): string {
    return 'sha256:' + createHash('sha256').update(xmlFirmado, 'utf8').digest('hex');
  }
}

export const FIRMAR_DOCUMENTO_PROVIDER = {
  provide: FIRMAR_DOCUMENTO_USE_CASE,
  useClass: FirmarDocumentoService,
};
