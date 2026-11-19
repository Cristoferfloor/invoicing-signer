import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

import { CifradorPort } from '../../domain/ports/cifrador.port';

const VERSION = 1;
const LARGO_IV = 12;
const LARGO_TAG = 16;

// Formato de lo guardado: version (1 byte) | iv (12) | tag (16) | cifrado.
// La version permite rotar la llave maestra mas adelante sin perder lo viejo.
export class AesGcmCifradorAdapter implements CifradorPort {
  private readonly llave: Buffer;

  constructor(llaveBase64: string | undefined) {
    const llave = Buffer.from(llaveBase64 ?? '', 'base64');
    if (llave.length !== 32) {
      throw new Error(
        'SIGNER_MASTER_KEY debe ser una llave de 32 bytes en base64 (openssl rand -base64 32).',
      );
    }
    this.llave = llave;
  }

  cifrar(datos: Buffer, contexto: string): Buffer {
    const iv = randomBytes(LARGO_IV);
    const cifrador = createCipheriv('aes-256-gcm', this.llave, iv);
    cifrador.setAAD(Buffer.from(contexto, 'utf8'));
    const cifrado = Buffer.concat([cifrador.update(datos), cifrador.final()]);
    return Buffer.concat([Buffer.from([VERSION]), iv, cifrador.getAuthTag(), cifrado]);
  }

  descifrar(guardado: Buffer, contexto: string): Buffer {
    if (guardado[0] !== VERSION) {
      throw new Error(`Version de cifrado desconocida: ${guardado[0]}.`);
    }
    const iv = guardado.subarray(1, 1 + LARGO_IV);
    const tag = guardado.subarray(1 + LARGO_IV, 1 + LARGO_IV + LARGO_TAG);
    const cifrado = guardado.subarray(1 + LARGO_IV + LARGO_TAG);

    const descifrador = createDecipheriv('aes-256-gcm', this.llave, iv);
    descifrador.setAAD(Buffer.from(contexto, 'utf8'));
    descifrador.setAuthTag(tag);
    return Buffer.concat([descifrador.update(cifrado), descifrador.final()]);
  }
}
