# Evidencia preliminar (local, antes de la ejecución en GitHub Actions)

**Fecha:** 2026-10-23 · **Commit base:** `717f5ef` · **Herramienta:** `npm audit` sobre el lockfile generado con `npm install --package-lock-only --ignore-scripts` (mismo método que el job C3).
**Alcance:** dependencias del backend (`package.json` raíz). El frontend se analiza en el pipeline.
Reporte completo: `npm-audit.json`.

## Conteo por severidad
| Crítica | Alta | Media | Baja | Total |
|---|---|---|---|---|
| 7 | 18 | 12 | 2 | 39 |

## Críticas detectadas
| Paquete | Parche disponible | Amenaza Act. 2 |
|---|---|---|
| jsonwebtoken | Sí | ST-02 Falsificación de JWT · ST-22 |
| crypto-js | Sí | ST-04 Reversión de hashes · ST-22 |
| lodash | Sí | ST-22 |
| decompress | Sí | ST-15 Archivo malicioso · ST-22 |
| tar | Sí | ST-15 · ST-22 |
| pdfkit | Sí | ST-22 |
| marsdb | **No** | ST-20 Manipulación de filtros · ST-22 |

Altas relevantes: `express-jwt` y `jws` (ST-02), `sanitize-html` (ST-19 XSS), `sqlite3` y `moment` (ST-22).

## Lectura esperada para el quality gate
- QG-03 (SCA) **bloqueará**: hay críticas y altas con parche.
- `marsdb` no tiene parche: según la política, una crítica bloquea aunque no haya versión corregida. Debe aceptarse con excepción justificada o reemplazarse.
- Secretos: `lib/insecurity.ts` línea 21 contiene una clave privada RSA en texto plano. QG-01 **bloqueará** (ST-23, ST-02).

> Esta evidencia es preliminar. El reporte oficial usa los artefactos de la ejecución 1 y 2 del pipeline.
