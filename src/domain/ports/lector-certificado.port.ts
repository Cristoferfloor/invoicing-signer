import { CertificadoDigital } from '../model/certificado-digital.model';

export const LECTOR_CERTIFICADO_PORT = Symbol('LECTOR_CERTIFICADO_PORT');

export interface CertificadoLeido {
  certificado: CertificadoDigital;
  emisor: string;
  numeroSerie: string;
  identificaciones: string[];
}

export interface LectorCertificadoPort {
  leer(contenido: Buffer, clave: string, ref: string): Promise<CertificadoLeido>;
}
