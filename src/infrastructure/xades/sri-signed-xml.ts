import * as xadesjs from 'xadesjs';
import * as XmlDSigJs from 'xmldsigjs';

import { emisorRfc2253 } from './emisor-rfc2253';

const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';

/**
 * xadesjs produce una firma XAdES-BES correcta segun el estandar, pero le
 * faltan dos bloques que si trae la firma que el SRI viene autorizando:
 *
 *  1. Una tercera <ds:Reference> que apunta al <ds:KeyInfo>, es decir, el
 *     bloque del certificado tambien queda firmado.
 *  2. <SignedDataObjectProperties> con el <DataObjectFormat> del comprobante.
 *
 * Ninguno de los dos se puede pedir por las opciones de Sign(), asi que se
 * agregan en ApplySignOptions, que corre antes de calcular los digests.
 */
export class SriSignedXml extends xadesjs.SignedXml {
  private idKeyInfo = '';
  private idReferenciaDocumento = '';

  configurarSri(idKeyInfo: string, idReferenciaDocumento: string): void {
    this.idKeyInfo = idKeyInfo;
    this.idReferenciaDocumento = idReferenciaDocumento;
  }

  protected async ApplySignOptions(
    signature: XmlDSigJs.Signature,
    algorithm: Algorithm,
    key: CryptoKey,
    options: xadesjs.OptionsXAdES,
  ): Promise<void> {
    await super.ApplySignOptions(signature, algorithm, key, options);

    this.emisorComoRfc2253(options);
    this.agregarDataObjectFormat();
    this.agregarReferenciaKeyInfo(signature);
  }

  // El emisor va como lo escribia la firma que el SRI autoriza (ver emisor-rfc2253.ts).
  private emisorComoRfc2253(options: xadesjs.OptionsXAdES): void {
    const opcion = options.signingCertificate;
    const certificado = typeof opcion === 'string' ? opcion : opcion?.certificate;
    const certificados =
      this.Properties?.SignedProperties?.SignedSignatureProperties?.SigningCertificate;

    if (!certificado || !certificados?.Count) {
      return;
    }

    certificados.Item(0)!.IssuerSerial.X509IssuerName = emisorRfc2253(certificado);
  }

  private agregarDataObjectFormat(): void {
    const propiedades =
      this.Properties?.SignedProperties?.SignedDataObjectProperties;

    if (!propiedades) {
      return;
    }

    const formato = new xadesjs.xml.DataObjectFormat();
    formato.ObjectReference = `#${this.idReferenciaDocumento}`;
    formato.Description = 'contenido comprobante';
    formato.MimeType = 'text/xml';

    propiedades.DataObjectFormats.Add(formato);
  }

  private agregarReferenciaKeyInfo(signature: XmlDSigJs.Signature): void {
    signature.KeyInfo.Id = this.idKeyInfo;

    const referencia = new XmlDSigJs.Reference();
    referencia.Uri = `#${this.idKeyInfo}`;
    referencia.DigestMethod.Algorithm = SHA1;

    signature.SignedInfo.References.Add(referencia);
  }
}
