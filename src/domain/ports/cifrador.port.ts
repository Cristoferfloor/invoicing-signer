export const CIFRADOR_PORT = Symbol('CIFRADOR_PORT');

export interface CifradorPort {
  // El contexto amarra el dato cifrado a su registro: un valor copiado a otra
  // fila no se puede descifrar.
  cifrar(datos: Buffer, contexto: string): Buffer;
  descifrar(cifrado: Buffer, contexto: string): Buffer;
}
