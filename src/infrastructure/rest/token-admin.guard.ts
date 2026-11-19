import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash, timingSafeEqual } from 'node:crypto';
import { Request } from 'express';

// Cargar o ver certificados es una operacion de administracion. Mientras no
// exista el panel con usuarios, se protege con un token del servicio.
@Injectable()
export class TokenAdminGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(contexto: ExecutionContext): boolean {
    const esperado = this.config.get<string>('SIGNER_ADMIN_TOKEN');
    if (!esperado) {
      throw new ServiceUnavailableException('La administracion de certificados no esta habilitada (falta SIGNER_ADMIN_TOKEN).');
    }

    const recibido = contexto.switchToHttp().getRequest<Request>().header('x-token-admin') ?? '';
    const iguales = timingSafeEqual(this.resumen(recibido), this.resumen(esperado));
    if (!iguales) throw new ForbiddenException('Token de administracion invalido.');
    return true;
  }

  private resumen(valor: string): Buffer {
    return createHash('sha256').update(valor).digest();
  }
}
