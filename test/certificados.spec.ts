import { randomBytes } from 'node:crypto';
import * as forge from 'node-forge';

import { AesGcmCifradorAdapter } from '../src/infrastructure/cifrado/aes-gcm-cifrador.adapter';
import { NodeForgeLectorAdapter } from '../src/infrastructure/certificados/node-forge-lector.adapter';
import { esRucValido, perteneceAEmpresa } from '../src/domain/certificado-empresa';

// Certificado de prueba con la misma forma que los de Security Data: la
// cedula del titular en el numero de serie del sujeto y el RUC de la empresa
// en la extension 1.3.6.1.4.1.37746.3.11.
function crearP12(ruc: string, cedula: string, clave: string): Buffer {
  const llaves = forge.pki.rsa.generateKeyPair({ bits: 1024, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = llaves.publicKey;
  cert.serialNumber = '74a9f568f969fafc';
  cert.validity.notBefore = new Date(Date.now() - 86_400_000);
  cert.validity.notAfter = new Date(Date.now() + 365 * 86_400_000);
  const sujeto = [
    { shortName: 'CN', value: 'TITULAR DE PRUEBA' },
    { name: 'serialNumber', value: `${cedula}-280426085116` },
  ];
  cert.setSubject(sujeto);
  cert.setIssuer([{ shortName: 'CN', value: 'CA DE PRUEBA' }]);
  cert.setExtensions([
    {
      id: '1.3.6.1.4.1.37746.3.11',
      value: forge.asn1.toDer(forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.UTF8, false, ruc)).getBytes(),
    },
  ]);
  cert.sign(llaves.privateKey, forge.md.sha256.create());

  const p12 = forge.pkcs12.toPkcs12Asn1(llaves.privateKey, [cert], clave, { algorithm: '3des' });
  return Buffer.from(forge.asn1.toDer(p12).getBytes(), 'binary');
}

describe('cifrado de certificados (AES-256-GCM)', () => {
  const cifrador = new AesGcmCifradorAdapter(randomBytes(32).toString('base64'));

  it('descifra lo que cifro con el mismo contexto', () => {
    const cifrado = cifrador.cifrar(Buffer.from('clave-secreta'), 'certificado:1790598616001:id:clave');
    expect(cifrado.includes(Buffer.from('clave-secreta'))).toBe(false);
    expect(cifrador.descifrar(cifrado, 'certificado:1790598616001:id:clave').toString()).toBe('clave-secreta');
  });

  it('no descifra un valor copiado a otro registro', () => {
    const cifrado = cifrador.cifrar(Buffer.from('clave-secreta'), 'certificado:1790598616001:a:clave');
    expect(() => cifrador.descifrar(cifrado, 'certificado:2390625475001:a:clave')).toThrow();
  });

  it('detecta un valor alterado', () => {
    const cifrado = cifrador.cifrar(Buffer.from('clave-secreta'), 'ctx');
    cifrado[cifrado.length - 1] ^= 0xff;
    expect(() => cifrador.descifrar(cifrado, 'ctx')).toThrow();
  });

  it('exige una llave de 32 bytes', () => {
    expect(() => new AesGcmCifradorAdapter('corta')).toThrow(/32 bytes/);
  });
});

describe('pertenencia del certificado a la empresa', () => {
  it('acepta el RUC de la empresa', () => {
    expect(perteneceAEmpresa('2390625475001', ['1714417860', '2390625475001'])).toBe(true);
  });

  it('rechaza un certificado de otra empresa', () => {
    expect(perteneceAEmpresa('1790598616001', ['1714417860', '2390625475001'])).toBe(false);
  });

  it('acepta la cedula para personas naturales, no para sociedades', () => {
    expect(perteneceAEmpresa('1714417860001', ['1714417860'])).toBe(true);
    expect(perteneceAEmpresa('1790598616001', ['1790598616'])).toBe(false);
  });

  it('valida el formato del RUC', () => {
    expect(esRucValido('2390625475001')).toBe(true);
    expect(esRucValido('239062547500')).toBe(false);
    expect(esRucValido('2390625475000')).toBe(false);
  });
});

describe('lectura del .p12', () => {
  const lector = new NodeForgeLectorAdapter();
  const p12 = crearP12('2390625475001', '1714417860', 'clave-p12');

  it('extrae titular, emisor e identificaciones', async () => {
    const leido = await lector.leer(p12, 'clave-p12', 'prueba');
    expect(leido.certificado.sujeto).toBe('TITULAR DE PRUEBA');
    expect(leido.emisor).toBe('CA DE PRUEBA');
    expect(leido.numeroSerie).toBe(BigInt('0x74a9f568f969fafc').toString());
    expect(leido.identificaciones).toEqual(expect.arrayContaining(['1714417860', '2390625475001']));
  });

  it('rechaza una clave incorrecta', async () => {
    await expect(lector.leer(p12, 'otra', 'prueba')).rejects.toThrow(/clave incorrecta/);
  });
});
