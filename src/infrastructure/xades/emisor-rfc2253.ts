import * as forge from 'node-forge';

/**
 * Emisor del certificado en formato RFC 2253, que es como lo escribia la firma
 * que el SRI viene autorizando:
 *
 *   CN=Lazzate Emisor CA,OU=Ente de Certificacion,O=Lazzate Cia. Ltda.,
 *   2.5.4.97=#13053539333832,1.2.840.113549.1.9.1=#1615...,L=Quito,C=EC
 *
 * xadesjs lo escribe al reves, con espacios y con nombres propios (E=, OIDs
 * con el valor en texto); con emisores que traen correo u otros campos fuera
 * de los basicos (Lazzate) el SRI responde "no se ajusta a XAdES".
 *
 * Se lee de los bytes del certificado para respetar el orden y la codificacion
 * originales de cada campo.
 */
const NOMBRES: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.9': 'STREET',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '0.9.2342.19200300.100.1.1': 'UID',
  '0.9.2342.19200300.100.1.25': 'DC',
};

const T = forge.asn1.Type;

export function emisorRfc2253(certificadoBase64: string): string {
  const certificado = forge.asn1.fromDer(forge.util.decode64(certificadoBase64));
  const tbs = (certificado.value as forge.asn1.Asn1[])[0];
  const campos = tbs.value as forge.asn1.Asn1[];
  // La version es opcional ([0]); despues vienen serie, algoritmo y emisor.
  const inicio = campos[0].tagClass === forge.asn1.Class.CONTEXT_SPECIFIC ? 1 : 0;
  const emisor = campos[inicio + 2].value as forge.asn1.Asn1[];

  return emisor
    .slice()
    .reverse()
    .map((rdn) => (rdn.value as forge.asn1.Asn1[]).map(atributo).join('+'))
    .join(',');
}

function atributo(nodo: forge.asn1.Asn1): string {
  const [tipo, valor] = nodo.value as forge.asn1.Asn1[];
  const oid = forge.asn1.derToOid(tipo.value as string);
  const nombre = NOMBRES[oid];
  const texto = nombre ? comoTexto(valor) : null;

  if (nombre && texto !== null) {
    return `${nombre}=${escapar(texto)}`;
  }
  return `${oid}=#${forge.asn1.toDer(valor).toHex()}`;
}

function comoTexto(valor: forge.asn1.Asn1): string | null {
  const bytes = valor.value as string;
  switch (valor.type as number) {
    case T.UTF8:
      return forge.util.decodeUtf8(bytes);
    case T.PRINTABLESTRING:
    case T.IA5STRING:
    case 20: // TeletexString (node-forge no le da nombre)
      return bytes;
    case T.BMPSTRING: {
      let texto = '';
      for (let i = 0; i + 1 < bytes.length; i += 2) {
        texto += String.fromCharCode((bytes.charCodeAt(i) << 8) | bytes.charCodeAt(i + 1));
      }
      return texto;
    }
    default:
      return null;
  }
}

function escapar(texto: string): string {
  let r = texto.replace(/([,+"\\<>;])/g, '\\$1');
  if (r.startsWith('#') || r.startsWith(' ')) r = `\\${r}`;
  if (r.endsWith(' ') && !r.endsWith('\\ ')) r = `${r.slice(0, -1)}\\ `;
  return r;
}
