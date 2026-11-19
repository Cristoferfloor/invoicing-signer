export interface CertificadoDigital {
  ref: string;
  clavePrivada: CryptoKey;
  // El SRI espera KeyValue/RSAKeyValue dentro de KeyInfo, que se construye
  // a partir de la clave publica del certificado.
  clavePublica: CryptoKey;
  certificadoBase64: string;
  sujeto: string;
  validoDesde: Date;
  validoHasta: Date;
}
