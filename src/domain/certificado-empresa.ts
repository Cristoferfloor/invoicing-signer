// Reglas para aceptar un certificado como firma de una empresa.

const RUC = /^\d{10}00[1-9]$/;

export function esRucValido(ruc: string): boolean {
  return RUC.test(ruc);
}

// Un certificado pertenece a la empresa si trae su RUC. Para personas
// naturales (tercer digito menor a 6) el RUC es la cedula mas 001, y hay
// certificados que solo traen la cedula.
export function perteneceAEmpresa(ruc: string, identificaciones: string[]): boolean {
  if (identificaciones.includes(ruc)) return true;

  const esPersonaNatural = Number(ruc[2]) < 6;
  return esPersonaNatural && identificaciones.includes(ruc.slice(0, 10));
}
