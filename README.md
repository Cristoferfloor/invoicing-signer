# invoicing-signer

Firma electrónica XAdES-BES de los comprobantes, con los certificados cifrados en Postgres.

Parte de la facturación electrónica V2 para el SRI de Ecuador. NestJS + TypeScript.

## Puerto

`3001` — `GET /salud` devuelve el estado del servicio.

## Arranque

```bash
cp .env.example .env    # completar los valores
npm ci
npm run build
npm run start:prod
```

Antes hay que levantar la red y las bases de
[invoicing-infrastructure](https://github.com/Cristoferfloor/invoicing-infrastructure).
