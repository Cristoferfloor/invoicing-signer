import {
  CertificadoCifrado,
  CertificadoRegistrado,
} from '../model/certificado-registrado.model';

export const REPOSITORIO_CERTIFICADOS_PORT = Symbol('REPOSITORIO_CERTIFICADOS_PORT');

export interface RepositorioCertificadosPort {
  guardarComoActivo(certificado: CertificadoCifrado): Promise<string[]>;
  obtenerActivo(empresaRuc: string): Promise<CertificadoCifrado | null>;
  listar(empresaRuc: string): Promise<CertificadoRegistrado[]>;
}
