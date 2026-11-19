import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { existsSync, readFileSync } from 'node:fs';
import { resolve, sep } from 'node:path';

import { AlmacenCertificadosPort } from '../../domain/ports/almacen-certificados.port';
import {
  LECTOR_CERTIFICADO_PORT,
  LectorCertificadoPort,
} from '../../domain/ports/lector-certificado.port';
import { CertificadoDigital } from '../../domain/model/certificado-digital.model';
import {
  CertificadoInvalidoError,
  CertificadoNoEncontradoError,
} from '../../domain/errors/firmador.errors';

// El ref llega desde una peticion HTTP y termina formando parte de una ruta
// de archivo: solo se aceptan refs sin separadores ni puntos.
const REF_VALIDO = /^[A-Za-z0-9_-]{1,64}$/;

interface EntradaCache {
  certificado: CertificadoDigital;
  cargadoEn: number;
}

// Almacen para desarrollo: .p12 en una carpeta y claves en variables de
// entorno. En el flujo se usa el almacen cifrado en Postgres.
@Injectable()
export class FilesystemCertificadoAdapter implements AlmacenCertificadosPort {
  private readonly logger = new Logger(FilesystemCertificadoAdapter.name);
  private readonly cache = new Map<string, EntradaCache>();
  private readonly directorio: string;
  private readonly ttlMs: number;

  constructor(
    private readonly config: ConfigService,
    @Inject(LECTOR_CERTIFICADO_PORT)
    private readonly lector: LectorCertificadoPort,
  ) {
    this.directorio = resolve(
      this.config.get<string>('FIRMADOR_CERT_DIR', '/certificados'),
    );
    this.ttlMs = Number(
      this.config.get<string>('SIGNER_CERT_CACHE_TTL_MS', '3600000'),
    );
  }

  async obtener(ref: string): Promise<CertificadoDigital> {
    const enCache = this.cache.get(ref);
    if (enCache && Date.now() - enCache.cargadoEn < this.ttlMs) {
      return enCache.certificado;
    }

    const certificado = await this.cargar(ref);
    this.cache.set(ref, { certificado, cargadoEn: Date.now() });
    return certificado;
  }

  private async cargar(ref: string): Promise<CertificadoDigital> {
    if (!REF_VALIDO.test(ref)) {
      throw new CertificadoNoEncontradoError(
        `La referencia de certificado "${ref}" no tiene un formato valido.`,
      );
    }

    // PKCS#12 viene indistintamente como .p12 o .pfx segun la CA emisora.
    const rutas = ['p12', 'pfx', 'P12', 'PFX'].map((ext) =>
      resolve(this.directorio, `${ref}.${ext}`),
    );

    if (rutas.some((r) => !r.startsWith(this.directorio + sep))) {
      throw new CertificadoNoEncontradoError(
        `La referencia de certificado "${ref}" no tiene un formato valido.`,
      );
    }

    const ruta = rutas.find((r) => existsSync(r));

    if (!ruta) {
      throw new CertificadoNoEncontradoError(
        `No existe el certificado "${ref}" en el almacen (.p12 ni .pfx).`,
      );
    }

    const { certificado } = await this.lector.leer(
      this.leerArchivo(ruta, ref),
      this.obtenerClaveDelCertificado(ref),
      ref,
    );

    this.logger.log(
      JSON.stringify({ evento: 'certificado_cargado', certificadoRef: ref }),
    );

    return certificado;
  }

  // El .p12 es una credencial y suele estar en modo 600: si el usuario del
  // contenedor no coincide con el dueno del archivo, el fallo debe decirlo,
  // no salir como un error generico de disco.
  private leerArchivo(ruta: string, ref: string): Buffer {
    try {
      return readFileSync(ruta);
    } catch (error) {
      const codigo = (error as NodeJS.ErrnoException).code;

      if (codigo === 'EACCES' || codigo === 'EPERM') {
        throw new CertificadoInvalidoError(
          `Sin permisos para leer el certificado "${ref}". Verifique que el usuario del contenedor pueda leer el archivo.`,
        );
      }

      throw new CertificadoNoEncontradoError(
        `No se pudo leer el certificado "${ref}": ${codigo ?? 'error desconocido'}.`,
      );
    }
  }

  private obtenerClaveDelCertificado(ref: string): string {
    const especifica = this.config.get<string>(
      `CERT_PASSWORD_${ref.toUpperCase().replace(/-/g, '_')}`,
    );
    const porDefecto = this.config.get<string>(
      'SIGNER_CERT_PASSWORD_DEFAULT',
    );
    const clave = especifica ?? porDefecto;

    if (clave === undefined || clave === '') {
      throw new CertificadoInvalidoError(
        `No hay clave configurada para el certificado "${ref}".`,
      );
    }

    return clave;
  }
}
