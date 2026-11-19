import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { AlmacenCertificadosPort } from '../domain/ports/almacen-certificados.port';
import {
  LECTOR_CERTIFICADO_PORT,
  LectorCertificadoPort,
} from '../domain/ports/lector-certificado.port';
import {
  REPOSITORIO_CERTIFICADOS_PORT,
  RepositorioCertificadosPort,
} from '../domain/ports/repositorio-certificados.port';
import { CIFRADOR_PORT, CifradorPort } from '../domain/ports/cifrador.port';
import { CertificadoDigital } from '../domain/model/certificado-digital.model';
import { CertificadoNoEncontradoError } from '../domain/errors/firmador.errors';

export function contextoCifrado(empresaRuc: string, id: string, campo: 'p12' | 'clave'): string {
  return `certificado:${empresaRuc}:${id}:${campo}`;
}

interface EntradaCache {
  certificado: CertificadoDigital;
  cargadoEn: number;
}

// Almacen de produccion: el certificado activo de cada empresa, cifrado en
// la base del firmador. La referencia del certificado es el RUC.
@Injectable()
export class AlmacenCifradoService implements AlmacenCertificadosPort {
  private readonly logger = new Logger(AlmacenCifradoService.name);
  private readonly cache = new Map<string, EntradaCache>();
  private readonly ttlMs: number;

  constructor(
    config: ConfigService,
    @Inject(REPOSITORIO_CERTIFICADOS_PORT)
    private readonly repositorio: RepositorioCertificadosPort,
    @Inject(CIFRADOR_PORT)
    private readonly cifrador: CifradorPort,
    @Inject(LECTOR_CERTIFICADO_PORT)
    private readonly lector: LectorCertificadoPort,
  ) {
    this.ttlMs = Number(config.get<string>('SIGNER_CERT_CACHE_TTL_MS', '3600000'));
  }

  async obtener(empresaRuc: string): Promise<CertificadoDigital> {
    const enCache = this.cache.get(empresaRuc);
    if (enCache && Date.now() - enCache.cargadoEn < this.ttlMs) {
      return enCache.certificado;
    }

    const guardado = await this.repositorio.obtenerActivo(empresaRuc);
    if (!guardado) {
      throw new CertificadoNoEncontradoError(
        `La empresa ${empresaRuc} no tiene un certificado activo cargado.`,
      );
    }

    const archivo = this.cifrador.descifrar(
      guardado.p12Cifrado,
      contextoCifrado(empresaRuc, guardado.id, 'p12'),
    );
    const clave = this.cifrador
      .descifrar(guardado.claveCifrada, contextoCifrado(empresaRuc, guardado.id, 'clave'))
      .toString('utf8');

    const { certificado } = await this.lector.leer(archivo, clave, empresaRuc);
    this.cache.set(empresaRuc, { certificado, cargadoEn: Date.now() });

    this.logger.log(
      JSON.stringify({ evento: 'certificado_cargado', empresaRuc, certificadoId: guardado.id }),
    );
    return certificado;
  }

  // Al cargar un certificado nuevo, esta copia deja de usar el anterior de
  // inmediato. Otras copias del servicio lo toman al vencer su cache.
  olvidar(empresaRuc: string): void {
    this.cache.delete(empresaRuc);
  }
}
