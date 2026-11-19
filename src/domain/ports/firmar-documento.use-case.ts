import { SolicitudFirma } from '../model/solicitud-firma.model';
import { ResultadoFirma } from '../model/resultado-firma.model';

export const FIRMAR_DOCUMENTO_USE_CASE = Symbol('FIRMAR_DOCUMENTO_USE_CASE');

export interface FirmarDocumentoUseCase {
  firmar(solicitud: SolicitudFirma): Promise<ResultadoFirma>;
}
