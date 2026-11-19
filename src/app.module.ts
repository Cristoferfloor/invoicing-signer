import { DynamicModule, Module, Provider, Type } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { FIRMAR_DOCUMENTO_PROVIDER } from './application/firmar-documento.service';
import { AlmacenCifradoService } from './application/almacen-cifrado.service';
import { REGISTRAR_CERTIFICADO_PROVIDER } from './application/registrar-certificado.service';
import { ALMACEN_CERTIFICADOS_PORT } from './domain/ports/almacen-certificados.port';
import { FIRMADOR_XML_PORT } from './domain/ports/firmador-xml.port';
import { LECTOR_CERTIFICADO_PORT } from './domain/ports/lector-certificado.port';
import { REPOSITORIO_CERTIFICADOS_PORT } from './domain/ports/repositorio-certificados.port';
import { CIFRADOR_PORT } from './domain/ports/cifrador.port';
import { FilesystemCertificadoAdapter } from './infrastructure/certificados/filesystem-certificado.adapter';
import { NodeForgeLectorAdapter } from './infrastructure/certificados/node-forge-lector.adapter';
import { AesGcmCifradorAdapter } from './infrastructure/cifrado/aes-gcm-cifrador.adapter';
import { PostgresCertificadosRepository } from './infrastructure/postgres/postgres-certificados.repository';
import { XadesBesSignerAdapter } from './infrastructure/xades/xades-bes-signer.adapter';
import { CertificadosController } from './infrastructure/rest/certificados.controller';
import { FirmaController } from './infrastructure/rest/firma.controller';
import { SaludController } from './infrastructure/rest/salud.controller';

// De donde salen los certificados depende del entorno:
//   SIGNER_STORE=archivos  .p12 en carpeta y claves en variables (desarrollo)
//   SIGNER_STORE=postgres  certificados cifrados en la base del firmador
@Module({})
export class AppModule {
  static registrar(env: NodeJS.ProcessEnv): DynamicModule {
    const controllers: Type[] = [FirmaController, SaludController];
    const providers: Provider[] = [
      FIRMAR_DOCUMENTO_PROVIDER,
      { provide: FIRMADOR_XML_PORT, useClass: XadesBesSignerAdapter },
      { provide: LECTOR_CERTIFICADO_PORT, useClass: NodeForgeLectorAdapter },
    ];

    if ((env.SIGNER_STORE ?? 'archivos') === 'postgres') {
      controllers.push(CertificadosController);
      providers.push(
        { provide: CIFRADOR_PORT, useValue: new AesGcmCifradorAdapter(env.SIGNER_MASTER_KEY) },
        { provide: REPOSITORIO_CERTIFICADOS_PORT, useValue: new PostgresCertificadosRepository(env.SIGNER_PG_URL) },
        AlmacenCifradoService,
        { provide: ALMACEN_CERTIFICADOS_PORT, useExisting: AlmacenCifradoService },
        REGISTRAR_CERTIFICADO_PROVIDER,
      );
    } else {
      providers.push({ provide: ALMACEN_CERTIFICADOS_PORT, useClass: FilesystemCertificadoAdapter });
    }

    return {
      module: AppModule,
      imports: [ConfigModule.forRoot({ isGlobal: true })],
      controllers,
      providers,
    };
  }
}
