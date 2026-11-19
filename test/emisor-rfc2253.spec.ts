import * as forge from 'node-forge';

import { emisorRfc2253 } from '../src/infrastructure/xades/emisor-rfc2253';
import { NodeForgeLectorAdapter } from '../src/infrastructure/certificados/node-forge-lector.adapter';
import { XadesBesSignerAdapter } from '../src/infrastructure/xades/xades-bes-signer.adapter';
const T = forge.asn1.Type;

const EMISOR_LAZZATE = [
  { shortName: 'C', value: 'EC', valueTagClass: T.PRINTABLESTRING },
  { shortName: 'ST', value: 'Quito - Pichincha', valueTagClass: T.UTF8 },
  { shortName: 'L', value: 'Quito', valueTagClass: T.UTF8 },
  { type: '1.2.840.113549.1.9.1', value: 'certificados@enext.ec', valueTagClass: T.IA5STRING },
  { type: '2.5.4.97', value: '59382', valueTagClass: T.PRINTABLESTRING },
  { shortName: 'O', value: 'Lazzate Cia. Ltda.', valueTagClass: T.UTF8 },
  { shortName: 'OU', value: 'Ente de Certificacion', valueTagClass: T.UTF8 },
  { shortName: 'CN', value: 'Lazzate Emisor CA', valueTagClass: T.UTF8 },
] as unknown as forge.pki.CertificateField[];

// Como lo escribia la firma que el SRI autorizo en septiembre con el certificado de Lazzate.
const EMISOR_LAZZATE_SRI =
  'CN=Lazzate Emisor CA,OU=Ente de Certificacion,O=Lazzate Cia. Ltda.,' +
  '2.5.4.97=#13053539333832,' +
  '1.2.840.113549.1.9.1=#1615636572746966696361646f7340656e6578742e6563,' +
  'L=Quito,ST=Quito - Pichincha,C=EC';

function crearCertificado(emisor: forge.pki.CertificateField[]) {
  const llaves = forge.pki.rsa.generateKeyPair({ bits: 1024, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = llaves.publicKey;
  cert.serialNumber = '0e3c62b5c6c87e3b7c5c50b46f27c22eb0a43f30';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(Date.now() + 86_400_000);
  cert.setSubject([{ shortName: 'CN', value: 'TITULAR DE PRUEBA' }]);
  cert.setIssuer(emisor);
  cert.sign(llaves.privateKey, forge.md.sha256.create());
  return { cert, llaves };
}

function certificadoCon(emisor: forge.pki.CertificateField[]): string {
  const { cert } = crearCertificado(emisor);
  return forge.util.encode64(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes());
}

describe('emisorRfc2253', () => {
  it('escribe el emisor de Lazzate igual que la firma que el SRI autorizo', () => {
    expect(emisorRfc2253(certificadoCon(EMISOR_LAZZATE))).toBe(EMISOR_LAZZATE_SRI);
  });

  it('el XML firmado lleva ese emisor en SigningCertificate', async () => {
    const { cert, llaves } = crearCertificado(EMISOR_LAZZATE);
    const p12 = forge.pkcs12.toPkcs12Asn1(llaves.privateKey, [cert], 'clave', { algorithm: '3des' });
    const leido = await new NodeForgeLectorAdapter().leer(
      Buffer.from(forge.asn1.toDer(p12).getBytes(), 'binary'),
      'clave',
      'prueba',
    );

    const firmado = await new XadesBesSignerAdapter().firmar(
      '<?xml version="1.0" encoding="UTF-8"?><factura id="comprobante" version="1.0.0"><infoTributaria><ruc>1790598616001</ruc></infoTributaria></factura>',
      leido.certificado,
    );

    const emisor = /X509IssuerName>([^<]*)</.exec(firmado)?.[1];
    expect(emisor).toBe(EMISOR_LAZZATE_SRI);
  });

  it('con un emisor de solo campos basicos los deja como texto', () => {
    const cert = certificadoCon([
      { shortName: 'C', value: 'EC' },
      { shortName: 'O', value: 'SECURITY DATA S.A. 2' },
      { shortName: 'OU', value: 'ENTIDAD DE CERTIFICACION DE INFORMACION' },
      { shortName: 'CN', value: 'AUTORIDAD DE CERTIFICACION SUBCA-2 SECURITY DATA' },
    ]);

    expect(emisorRfc2253(cert)).toBe(
      'CN=AUTORIDAD DE CERTIFICACION SUBCA-2 SECURITY DATA,OU=ENTIDAD DE CERTIFICACION DE INFORMACION,' +
        'O=SECURITY DATA S.A. 2,C=EC',
    );
  });
});
