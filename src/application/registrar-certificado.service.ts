import { Inject, Injectable, Logger } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';

import {
  REGISTRAR_CERTIFICADO_USE_CASE,
  RegistrarCertificadoUseCase,
  ResultadoRegistroCertificado,
  SolicitudRegistroCertificado,
} from '../domain/ports/registrar-certificado.use-case';
import {
  LECTOR_CERTIFICADO_PORT,
  LectorCertificadoPort,
} from '../domain/ports/lector-certificado.port';
import {
  REPOSITORIO_CERTIFICADOS_PORT,
  RepositorioCertificadosPort,
} from '../domain/ports/repositorio-certificados.port';
import { CIFRADOR_PORT, CifradorPort } from '../domain/ports/cifrador.port';
import { CertificadoRegistrado } from '../domain/model/certificado-registrado.model';
import { perteneceAEmpresa } from '../domain/certificado-empresa';
import {
  CertificadoDeOtraEmpresaError,
  CertificadoVencidoError,
} from '../domain/errors/firmador.errors';
import { AlmacenCifradoService, contextoCifrado } from './almacen-cifrado.service';

@Injectable()
export class RegistrarCertificadoService implements RegistrarCertificadoUseCase {
  private readonly logger = new Logger(RegistrarCertificadoService.name);

  constructor(
    @Inject(LECTOR_CERTIFICADO_PORT)
    private readonly lector: LectorCertificadoPort,
    @Inject(REPOSITORIO_CERTIFICADOS_PORT)
    private readonly repositorio: RepositorioCertificadosPort,
    @Inject(CIFRADOR_PORT)
    private readonly cifrador: CifradorPort,
    private readonly almacen: AlmacenCifradoService,
  ) {}

  async registrar(
    solicitud: SolicitudRegistroCertificado,
  ): Promise<ResultadoRegistroCertificado> {
    const { empresaRuc, archivo, clave } = solicitud;

    // 1. Que abra con esa clave y tenga clave privada.
    const leido = await this.lector.leer(archivo, clave, empresaRuc);

    // 2. Que sea de la empresa.
    if (!perteneceAEmpresa(empresaRuc, leido.identificaciones)) {
      throw new CertificadoDeOtraEmpresaError(
        `El certificado de ${leido.certificado.sujeto} no pertenece al RUC ${empresaRuc}.`,
      );
    }

    // 3. Que este vigente.
    if (leido.certificado.validoHasta < new Date()) {
      throw new CertificadoVencidoError(
        `El certificado de ${leido.certificado.sujeto} vencio el ${leido.certificado.validoHasta.toISOString()}.`,
      );
    }

    const huella = createHash('sha256').update(archivo).digest('hex');

    const activo = await this.repositorio.obtenerActivo(empresaRuc);
    if (activo && activo.huella === huella) {
      return { certificado: this.visible(activo), yaExistia: true, reemplazados: [] };
    }

    const id = randomUUID();
    const ahora = new Date();
    const registro = {
      id,
      empresaRuc,
      titular: leido.certificado.sujeto,
      emisor: leido.emisor,
      numeroSerie: leido.numeroSerie,
      validoDesde: leido.certificado.validoDesde,
      validoHasta: leido.certificado.validoHasta,
      huella,
      estado: 'ACTIVO' as const,
      cargadoEn: ahora,
      reemplazadoEn: null,
    };

    const reemplazados = await this.repositorio.guardarComoActivo({
      ...registro,
      p12Cifrado: this.cifrador.cifrar(archivo, contextoCifrado(empresaRuc, id, 'p12')),
      claveCifrada: this.cifrador.cifrar(
        Buffer.from(clave, 'utf8'),
        contextoCifrado(empresaRuc, id, 'clave'),
      ),
    });

    this.almacen.olvidar(empresaRuc);

    this.logger.log(
      JSON.stringify({
        evento: 'certificado_registrado',
        empresaRuc,
        certificadoId: id,
        titular: registro.titular,
        validoHasta: registro.validoHasta.toISOString(),
        reemplazados,
      }),
    );

    return { certificado: registro, yaExistia: false, reemplazados };
  }

  listar(empresaRuc: string): Promise<CertificadoRegistrado[]> {
    return this.repositorio.listar(empresaRuc);
  }

  private visible(certificado: CertificadoRegistrado): CertificadoRegistrado {
    const { p12Cifrado: _p12, claveCifrada: _clave, ...visible } =
      certificado as CertificadoRegistrado & { p12Cifrado?: Buffer; claveCifrada?: Buffer };
    return visible;
  }
}

export const REGISTRAR_CERTIFICADO_PROVIDER = {
  provide: REGISTRAR_CERTIFICADO_USE_CASE,
  useClass: RegistrarCertificadoService,
};
