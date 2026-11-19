import { Injectable } from '@nestjs/common';
import * as forge from 'node-forge';
import { Crypto } from '@peculiar/webcrypto';

import {
  CertificadoLeido,
  LectorCertificadoPort,
} from '../../domain/ports/lector-certificado.port';
import { CertificadoInvalidoError } from '../../domain/errors/firmador.errors';

@Injectable()
export class NodeForgeLectorAdapter implements LectorCertificadoPort {
  private readonly crypto = new Crypto();

  async leer(
    contenido: Buffer,
    clave: string,
    ref: string,
  ): Promise<CertificadoLeido> {
    const { clavePrivadaPem, certificadoFirmante } = this.abrirP12(
      contenido,
      clave,
      ref,
    );

    const clavePrivada = await this.importarClavePrivada(clavePrivadaPem, ref);
    const clavePublica = await this.importarClavePublica(
      certificadoFirmante,
      ref,
    );

    return {
      certificado: {
        ref,
        clavePrivada,
        clavePublica,
        certificadoBase64: forge.util.encode64(
          forge.asn1
            .toDer(forge.pki.certificateToAsn1(certificadoFirmante))
            .getBytes(),
        ),
        sujeto: this.leerCampo(certificadoFirmante.subject, 'CN'),
        validoDesde: certificadoFirmante.validity.notBefore,
        validoHasta: certificadoFirmante.validity.notAfter,
      },
      emisor: this.leerCampo(certificadoFirmante.issuer, 'CN'),
      numeroSerie: BigInt(`0x${certificadoFirmante.serialNumber}`).toString(),
      identificaciones: this.leerIdentificaciones(certificadoFirmante),
    };
  }

  private abrirP12(
    contenido: Buffer,
    clave: string,
    ref: string,
  ): { clavePrivadaPem: string; certificadoFirmante: forge.pki.Certificate } {
    let p12: forge.pkcs12.Pkcs12Pfx;
    try {
      const der = forge.util.createBuffer(contenido.toString('binary'));
      p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(der), clave);
    } catch {
      throw new CertificadoInvalidoError(
        `No se pudo abrir el certificado "${ref}": clave incorrecta o archivo corrupto.`,
      );
    }

    let clavePrivada: forge.pki.PrivateKey | undefined;
    const certificados: forge.pki.Certificate[] = [];

    for (const safeContent of p12.safeContents) {
      for (const safeBag of safeContent.safeBags) {
        const esClave =
          safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag ||
          safeBag.type === forge.pki.oids.keyBag;

        if (esClave && safeBag.key) {
          clavePrivada = safeBag.key;
        } else if (safeBag.type === forge.pki.oids.certBag && safeBag.cert) {
          certificados.push(safeBag.cert);
        }
      }
    }

    // El .p12 trae el certificado del emisor junto con la cadena de la
    // autoridad certificadora. El que firma es el que corresponde a la clave
    // privada: se identifica comparando el modulo RSA, no por heuristicas
    // sobre basicConstraints.
    const certificadoFirmante = clavePrivada
      ? this.certificadoDeLaClave(certificados, clavePrivada)
      : undefined;

    if (!clavePrivada || !certificadoFirmante) {
      throw new CertificadoInvalidoError(
        `El certificado "${ref}" no contiene clave privada y certificado de firma.`,
      );
    }

    return {
      clavePrivadaPem: forge.pki.privateKeyToPem(clavePrivada),
      certificadoFirmante,
    };
  }

  private certificadoDeLaClave(
    certificados: forge.pki.Certificate[],
    clavePrivada: forge.pki.PrivateKey,
  ): forge.pki.Certificate | undefined {
    const modulo = (clavePrivada as forge.pki.rsa.PrivateKey).n;

    if (!modulo) {
      return certificados[0];
    }

    return certificados.find((cert) => {
      const publica = cert.publicKey as forge.pki.rsa.PublicKey | undefined;
      return publica?.n?.compareTo(modulo) === 0;
    });
  }

  private leerCampo(nombre: forge.pki.Certificate['subject'], campo: string): string {
    const valor = nombre.getField(campo) as { value?: string } | null;
    return valor?.value ?? '(sin CN)';
  }

  // Las CA ecuatorianas ponen la cedula del titular y el RUC de la empresa en
  // extensiones propias (Security Data: 1.3.6.1.4.1.37746.3.x) y a veces en el
  // numero de serie del sujeto. Como cada CA usa sus OID, se recogen todos los
  // numeros de 10 o 13 digitos del sujeto y de las extensiones.
  private leerIdentificaciones(cert: forge.pki.Certificate): string[] {
    const textos: string[] = cert.subject.attributes.map((a) => String(a.value ?? ''));

    for (const extension of cert.extensions as Array<{ value?: unknown }>) {
      if (typeof extension.value === 'string') {
        textos.push(...this.textosDeDer(extension.value));
      }
    }

    const identificaciones = new Set<string>();
    for (const texto of textos) {
      for (const numero of texto.match(/\d+/g) ?? []) {
        if (numero.length === 10 || numero.length === 13) identificaciones.add(numero);
      }
    }
    return [...identificaciones];
  }

  private textosDeDer(der: string): string[] {
    try {
      return this.textosDeAsn1(forge.asn1.fromDer(der));
    } catch {
      return [der];
    }
  }

  private textosDeAsn1(nodo: forge.asn1.Asn1): string[] {
    if (Array.isArray(nodo.value)) {
      return nodo.value.flatMap((hijo) => this.textosDeAsn1(hijo));
    }
    return typeof nodo.value === 'string' ? [nodo.value] : [];
  }

  // Los .p12 emitidos por las CAs ecuatorianas traen la clave en PKCS#1 o en
  // PKCS#8 segun el emisor; WebCrypto solo importa PKCS#8, asi que se convierte
  // cuando hace falta.
  private async importarClavePrivada(
    pem: string,
    ref: string,
  ): Promise<CryptoKey> {
    const parametros = {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-1',
    } as const;

    try {
      return await this.crypto.subtle.importKey(
        'pkcs8',
        this.pemADer(pem),
        parametros,
        false,
        ['sign'],
      );
    } catch {
      try {
        const clave = forge.pki.privateKeyFromPem(pem);
        const pkcs8Pem = forge.pki.privateKeyInfoToPem(
          forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(clave)),
        );

        return await this.crypto.subtle.importKey(
          'pkcs8',
          this.pemADer(pkcs8Pem),
          parametros,
          false,
          ['sign'],
        );
      } catch {
        throw new CertificadoInvalidoError(
          `No se pudo interpretar la clave privada del certificado "${ref}".`,
        );
      }
    }
  }

  private async importarClavePublica(
    cert: forge.pki.Certificate,
    ref: string,
  ): Promise<CryptoKey> {
    try {
      const pem = forge.pki.publicKeyToPem(
        cert.publicKey as forge.pki.rsa.PublicKey,
      );

      return await this.crypto.subtle.importKey(
        'spki',
        this.pemADer(pem),
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' },
        true,
        ['verify'],
      );
    } catch {
      throw new CertificadoInvalidoError(
        `No se pudo leer la clave publica del certificado "${ref}".`,
      );
    }
  }

  private pemADer(pem: string): ArrayBuffer {
    const base64 = pem
      .replace(/-----BEGIN [^-]+-----/g, '')
      .replace(/-----END [^-]+-----/g, '')
      .replace(/\s/g, '');

    const buffer = Buffer.from(base64, 'base64');

    return buffer.buffer.slice(
      buffer.byteOffset,
      buffer.byteOffset + buffer.byteLength,
    ) as ArrayBuffer;
  }
}
