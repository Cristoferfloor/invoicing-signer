import { CertificadoRegistrado } from '../model/certificado-registrado.model';

export const REGISTRAR_CERTIFICADO_USE_CASE = Symbol('REGISTRAR_CERTIFICADO_USE_CASE');

export interface SolicitudRegistroCertificado {
  empresaRuc: string;
  archivo: Buffer;
  clave: string;
}

export interface ResultadoRegistroCertificado {
  certificado: CertificadoRegistrado;
  yaExistia: boolean;
  reemplazados: string[];
}

export interface RegistrarCertificadoUseCase {
  registrar(solicitud: SolicitudRegistroCertificado): Promise<ResultadoRegistroCertificado>;
  listar(empresaRuc: string): Promise<CertificadoRegistrado[]>;
}
