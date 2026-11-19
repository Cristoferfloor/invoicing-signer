export type EstadoCertificado = 'ACTIVO' | 'REEMPLAZADO';

// Lo que se puede mostrar de un certificado cargado. Nunca lleva el .p12 ni
// su clave.
export interface CertificadoRegistrado {
  id: string;
  empresaRuc: string;
  titular: string;
  emisor: string;
  numeroSerie: string;
  validoDesde: Date;
  validoHasta: Date;
  huella: string;
  estado: EstadoCertificado;
  cargadoEn: Date;
  reemplazadoEn: Date | null;
}

// Como se guarda: los datos visibles mas el .p12 y la clave ya cifrados.
export interface CertificadoCifrado extends CertificadoRegistrado {
  p12Cifrado: Buffer;
  claveCifrada: Buffer;
}
