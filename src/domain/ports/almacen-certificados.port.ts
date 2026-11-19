import { CertificadoDigital } from '../model/certificado-digital.model';

export const ALMACEN_CERTIFICADOS_PORT = Symbol('ALMACEN_CERTIFICADOS_PORT');

export interface AlmacenCertificadosPort {
  obtener(ref: string): Promise<CertificadoDigital>;
}
