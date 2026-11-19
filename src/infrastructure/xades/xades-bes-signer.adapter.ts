import { Injectable } from '@nestjs/common';
import { Crypto } from '@peculiar/webcrypto';
import { DOMParser, XMLSerializer } from '@xmldom/xmldom';
import * as xadesjs from 'xadesjs';
import * as xmlCore from 'xml-core';
import { randomBytes } from 'node:crypto';

import { SriSignedXml } from './sri-signed-xml';

import { FirmadorXmlPort } from '../../domain/ports/firmador-xml.port';
import { CertificadoDigital } from '../../domain/model/certificado-digital.model';
import {
  FirmaFallidaError,
  XmlInvalidoError,
} from '../../domain/errors/firmador.errors';

// @xmldom/xmldom trae su propia jerarquia DOM, distinta de la del lib "DOM" de
// TypeScript; se derivan los tipos del propio parser para no mezclarlas.
type DocumentoXml = ReturnType<InstanceType<typeof DOMParser>['parseFromString']>;
type ElementoXml = NonNullable<DocumentoXml['documentElement']>;
type NodoXml = Parameters<ElementoXml['appendChild']>[0];

// El SRI espera la firma enveloped dentro del comprobante, referenciando al
// elemento raiz por su atributo id. Los XML del SRI ya traen id="comprobante";
// si llega uno sin id, se le asigna para que la referencia resuelva.
const ID_POR_DEFECTO = 'comprobante';

@Injectable()
export class XadesBesSignerAdapter implements FirmadorXmlPort {
  constructor() {
    xmlCore.setNodeDependencies({ DOMParser, XMLSerializer });
    xadesjs.Application.setEngine('NodeJS', new Crypto());
  }

  async firmar(xml: string, certificado: CertificadoDigital): Promise<string> {
    const documento = this.parsear(xml);
    const raiz = documento.documentElement;

    if (!raiz) {
      throw new XmlInvalidoError('El XML no tiene elemento raiz.');
    }

    const idReferencia = this.asegurarId(raiz);
    const nodoFirma = await this.generarFirma(
      documento,
      idReferencia,
      certificado,
    );

    raiz.appendChild(nodoFirma);

    return new XMLSerializer().serializeToString(documento);
  }

  private async generarFirma(
    documento: DocumentoXml,
    idReferencia: string,
    certificado: CertificadoDigital,
  ): Promise<NodoXml> {
    const firmador = new SriSignedXml();
    const idKeyInfo = `Certificate${this.idAleatorio()}`;
    const idReferenciaDocumento = `Reference-${idReferencia}`;

    firmador.configurarSri(idKeyInfo, idReferenciaDocumento);

    try {
      const firma = await firmador.Sign(
        { name: 'RSA-SHA1' },
        certificado.clavePrivada,
        documento as unknown as Document,
        {
          x509: [certificado.certificadoBase64],
          // El SRI espera KeyInfo con X509Data y ademas KeyValue/RSAKeyValue.
          keyValue: certificado.clavePublica,
          references: [
            {
              id: `Reference-${idReferencia}`,
              uri: `#${idReferencia}`,
              hash: 'SHA-1',
              // Solo enveloped: la canonicalizacion ya va declarada en
              // CanonicalizationMethod, igual que en los comprobantes que el
              // SRI viene autorizando.
              transforms: ['enveloped'],
            },
          ],
          // XAdES-BES exige SigningCertificate dentro de SignedProperties:
          // liga la firma a este certificado concreto. El digest va en SHA-1
          // para no mezclar algoritmos dentro de la misma firma.
          signingCertificate: {
            certificate: certificado.certificadoBase64,
            digestAlgorithm: 'SHA-1',
          },
          signingTime: { value: new Date() },
        },
      );

      const nodo = firma.GetXml();
      if (!nodo) {
        throw new Error('la libreria no devolvio un nodo de firma');
      }

      return nodo as unknown as NodoXml;
    } catch (error) {
      throw new FirmaFallidaError(
        `No se pudo generar la firma XAdES-BES: ${this.mensajeDe(error)}`,
      );
    }
  }

  private parsear(xml: string): DocumentoXml {
    try {
      const documento = new DOMParser().parseFromString(xml, 'application/xml');

      if (!documento?.documentElement) {
        throw new Error('sin elemento raiz');
      }

      return documento;
    } catch (error) {
      throw new XmlInvalidoError(
        `El XML recibido no se pudo interpretar: ${this.mensajeDe(error)}`,
      );
    }
  }

  private asegurarId(raiz: ElementoXml): string {
    const idExistente = raiz.getAttribute('id') ?? raiz.getAttribute('Id');

    if (idExistente) {
      return idExistente;
    }

    raiz.setAttribute('id', ID_POR_DEFECTO);
    return ID_POR_DEFECTO;
  }

  private idAleatorio(): string {
    return randomBytes(4).readUInt32BE(0).toString();
  }

  private mensajeDe(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
  }
}
