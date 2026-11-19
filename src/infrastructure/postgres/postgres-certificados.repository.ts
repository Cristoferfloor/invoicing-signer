import { Logger, OnApplicationShutdown, OnModuleInit } from '@nestjs/common';
import { Pool } from 'pg';

import { RepositorioCertificadosPort } from '../../domain/ports/repositorio-certificados.port';
import {
  CertificadoCifrado,
  CertificadoRegistrado,
} from '../../domain/model/certificado-registrado.model';

const ESQUEMA = `
CREATE TABLE IF NOT EXISTS certificados (
  id              uuid PRIMARY KEY,
  empresa_ruc     char(13)    NOT NULL,
  titular         text        NOT NULL,
  emisor          text        NOT NULL,
  numero_serie    text        NOT NULL,
  valido_desde    timestamptz NOT NULL,
  valido_hasta    timestamptz NOT NULL,
  huella_sha256   char(64)    NOT NULL,
  estado          text        NOT NULL CHECK (estado IN ('ACTIVO', 'REEMPLAZADO')),
  p12_cifrado     bytea       NOT NULL,
  clave_cifrada   bytea       NOT NULL,
  cargado_en      timestamptz NOT NULL DEFAULT now(),
  reemplazado_en  timestamptz
);

-- Un solo certificado activo por empresa: lo garantiza la base, no el codigo.
CREATE UNIQUE INDEX IF NOT EXISTS certificados_un_activo_por_empresa
  ON certificados (empresa_ruc) WHERE estado = 'ACTIVO';

CREATE INDEX IF NOT EXISTS certificados_por_vencimiento
  ON certificados (valido_hasta) WHERE estado = 'ACTIVO';
`;

const COLUMNAS_VISIBLES = `id, empresa_ruc, titular, emisor, numero_serie, valido_desde,
  valido_hasta, huella_sha256, estado, cargado_en, reemplazado_en`;

interface FilaCertificado {
  id: string;
  empresa_ruc: string;
  titular: string;
  emisor: string;
  numero_serie: string;
  valido_desde: Date;
  valido_hasta: Date;
  huella_sha256: string;
  estado: 'ACTIVO' | 'REEMPLAZADO';
  cargado_en: Date;
  reemplazado_en: Date | null;
  p12_cifrado?: Buffer;
  clave_cifrada?: Buffer;
}

export class PostgresCertificadosRepository
  implements RepositorioCertificadosPort, OnModuleInit, OnApplicationShutdown
{
  private readonly logger = new Logger(PostgresCertificadosRepository.name);
  private readonly pool: Pool;

  constructor(url: string | undefined) {
    if (!url) throw new Error('Falta SIGNER_PG_URL para el almacen de certificados.');
    this.pool = new Pool({ connectionString: url, max: 5 });
  }

  async onModuleInit(): Promise<void> {
    await this.pool.query(ESQUEMA);
    this.logger.log(JSON.stringify({ evento: 'esquema_certificados_listo' }));
  }

  async onApplicationShutdown(): Promise<void> {
    await this.pool.end();
  }

  async guardarComoActivo(c: CertificadoCifrado): Promise<string[]> {
    const cliente = await this.pool.connect();
    try {
      await cliente.query('BEGIN');
      const reemplazados = await cliente.query<{ id: string }>(
        `UPDATE certificados SET estado = 'REEMPLAZADO', reemplazado_en = now()
          WHERE empresa_ruc = $1 AND estado = 'ACTIVO' RETURNING id`,
        [c.empresaRuc],
      );
      await cliente.query(
        `INSERT INTO certificados (id, empresa_ruc, titular, emisor, numero_serie, valido_desde,
           valido_hasta, huella_sha256, estado, p12_cifrado, clave_cifrada, cargado_en)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'ACTIVO', $9, $10, $11)`,
        [
          c.id, c.empresaRuc, c.titular, c.emisor, c.numeroSerie, c.validoDesde,
          c.validoHasta, c.huella, c.p12Cifrado, c.claveCifrada, c.cargadoEn,
        ],
      );
      await cliente.query('COMMIT');
      return reemplazados.rows.map((fila) => fila.id);
    } catch (error) {
      await cliente.query('ROLLBACK');
      throw error;
    } finally {
      cliente.release();
    }
  }

  async obtenerActivo(empresaRuc: string): Promise<CertificadoCifrado | null> {
    const { rows } = await this.pool.query<FilaCertificado>(
      `SELECT ${COLUMNAS_VISIBLES}, p12_cifrado, clave_cifrada
         FROM certificados WHERE empresa_ruc = $1 AND estado = 'ACTIVO'`,
      [empresaRuc],
    );
    if (rows.length === 0) return null;
    const fila = rows[0];
    return { ...this.aModelo(fila), p12Cifrado: fila.p12_cifrado!, claveCifrada: fila.clave_cifrada! };
  }

  async listar(empresaRuc: string): Promise<CertificadoRegistrado[]> {
    const { rows } = await this.pool.query<FilaCertificado>(
      `SELECT ${COLUMNAS_VISIBLES} FROM certificados
        WHERE empresa_ruc = $1 ORDER BY cargado_en DESC`,
      [empresaRuc],
    );
    return rows.map((fila) => this.aModelo(fila));
  }

  private aModelo(fila: FilaCertificado): CertificadoRegistrado {
    return {
      id: fila.id,
      empresaRuc: fila.empresa_ruc,
      titular: fila.titular,
      emisor: fila.emisor,
      numeroSerie: fila.numero_serie,
      validoDesde: fila.valido_desde,
      validoHasta: fila.valido_hasta,
      huella: fila.huella_sha256,
      estado: fila.estado,
      cargadoEn: fila.cargado_en,
      reemplazadoEn: fila.reemplazado_en,
    };
  }
}
