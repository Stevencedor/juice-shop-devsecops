# 1. Definición del contexto

## Proyecto base
- **Repositorio:** fork de OWASP Juice Shop (`juice-shop/juice-shop`, rama `master`, versión 20.3.0, commit base `717f5ef`).
- **Por qué este sistema:** es el mismo sistema analizado en la Actividad 1 (requisitos y arquitectura) y en la Actividad 2 (STRIDE y matriz de riesgo). Así cada control del pipeline se justifica con un riesgo ST-nn ya priorizado.

## Tipo de aplicación
Aplicación web de comercio electrónico (SPA más API REST). Gestiona el ciclo catálogo → carrito → pedido → pago → entrega → posventa. Es deliberadamente vulnerable, por lo que se despliega solo en un clúster efímero sin datos reales.

## Stack tecnológico
| Capa | Tecnología |
|---|---|
| Frontend | Angular (TypeScript), compilado a estáticos servidos por la API |
| Backend / API | Node.js 24 + Express (TypeScript), autenticación con JWT |
| Persistencia | SQLite (Sequelize) y almacén documental en memoria (MarsDB) |
| Empaquetado | Docker multi-etapa: `node:24` (build) → `distroless/nodejs24` (runtime, usuario 65532) |
| Orquestación | Kubernetes (kind efímero en el runner), namespace con PSA *restricted* y NetworkPolicy |
| CI/CD | GitHub Actions (`.github/workflows/devsecops.yml`) |

## Flujo básico
| Etapa | Qué ocurre | Dónde |
|---|---|---|
| Build | `docker build` de la imagen; genera el artefacto desplegable | job `container` |
| Seguridad | Secretos, SAST, SCA, IaC, escaneo de imagen, SBOM y DAST | jobs C1–C7 |
| Test | Pruebas unitarias del servidor (`npm run test:server`) y del evaluador de gates; prueba dinámica (ZAP) y prueba de humo tras desplegar | jobs `unit-tests`, `dast` y `deploy-k8s` |
| Quality gate | Aplica umbrales y excepciones; decide bloquear, advertir o permitir | job `quality-gate` |
| Deploy | Despliegue en kind solo si el gate libera y las pruebas unitarias pasan; publicación en GHCR solo en la rama por defecto | jobs `deploy-k8s` y `publish` |

## Límites de confianza involucrados (Actividad 2)
- **TB-08 cadena de suministro:** dependencias npm e imagen base → controles C3, C4 y C6.
- **TB-09 plano de gestión:** secretos y manifiestos de despliegue → controles C1 y C5.
- **TB-01/TB-02 navegador y API:** superficie expuesta → controles C2 y C7.
