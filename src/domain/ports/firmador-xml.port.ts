import { CertificadoDigital } from '../model/certificado-digital.model';

export const FIRMADOR_XML_PORT = Symbol('FIRMADOR_XML_PORT');

export interface FirmadorXmlPort {
  firmar(xml: string, certificado: CertificadoDigital): Promise<string>;
}
