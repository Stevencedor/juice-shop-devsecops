# Reporte consolidado de hallazgos — Pipeline DevSecOps sobre OWASP Juice Shop

**Repositorio:** https://github.com/Stevencedor/juice-shop-devsecops · **Ramas:** `feature/devsecops-pipeline` → `master` (PR #1)
**Ejecución 1:** commit `c39085f` · 2026-10-24 · (https://github.com/Stevencedor/juice-shop-devsecops/actions/runs/40063793133)
**Ejecución 2:** commit `4048e46` · 2026-10-24 · (https://github.com/Stevencedor/juice-shop-devsecops/actions/runs/40130173330)
**Ejecución en master (publicación):** merge `85b1ad0` del PR #1 · 2026-10-24 · (https://github.com/Stevencedor/juice-shop-devsecops/actions/runs/40134086969)
**Ambiente:** laboratorio (GitHub Actions + kind efímero, sin datos reales). Evidencia en `evidencias/ejecucion1/` y `evidencias/ejecucion2/`.

## 1. Resumen ejecutivo

La primera ejecución analizó el código original de Juice Shop y el gate **bloqueó la liberación** en 6 de 8 controles. Era el resultado esperado: Juice Shop es deliberadamente vulnerable. Tras el triaje se corrigieron 3 hallazgos de la aplicación y 2 defectos del propio pipeline; el resto se clasificó como riesgo aceptado con responsable y vencimiento, o como falso positivo con razón técnica.

| Control | Gate | Ejecución 1 (código original) | Ejecución 2 (tras triaje) |
|---|---|---|---|
| Secretos | QG-01 | ⛔ 225 secretos (historial git) | ✅ 0 activos · 225 cubiertos por excepciones |
| SAST | QG-02 | ⛔ 3 altas · ⚠️ 17 medias | ⚠️ 0 altas (1 corregida, 2 aceptadas) · 17 medias |
| SCA | QG-03 | ⛔ 9 críticas · 28 altas con parche · 1 alta sin parche · 32 medias | ⚠️ 0 críticas/altas · 5 medias · 67 cubiertos |
| Contenedor | QG-04 | ⛔ 9 críticas · 26 altas con parche · 52 medias (+3 secretos altos no contados, ver P-02) | ⚠️ 0 secretos/críticas/altas · 28 medias · 64 cubiertos |
| IaC | QG-05 | ⛔ 25 críticas/altas · 4 medias | ✅ 0 activos · 49 cubiertos (2 hallazgos del Dockerfile corregidos) |
| SBOM | QG-06 | ✅ 2 744 componentes | ✅ 2 744 componentes |
| DAST | QG-07 | ⛔ SIN EVIDENCIA (defecto del pipeline, ver P-01) | ⚠️ 0 altas · 2 medias |
| Excepciones | QG-08 | ✅ sin excepciones | ✅ 50 excepciones completas y vigentes |
| **Decisión** | | **⛔ BLOQUEA** · deploy omitido | **⚠️ LIBERA con advertencias** · deploy y smoke test ✅ |

Fuente: `evidencias/ejecucion1/` y `evidencias/ejecucion2/quality-gate-result/gate-summary.md`. Una simulación local del evaluador con los reportes de la ejecución 1 había anticipado este mismo resultado antes del push.

**Despliegue de la ejecución 2** (`evidencias/ejecucion2/deploy-evidence/`): Deployment `1/1` disponible con la imagen `juice-shop:4048e46…`; pod `Running` sin reinicios; Service `ClusterIP` (sin exposición externa); NetworkPolicy `juice-shop-restrict` aplicada; `securityContext` con `runAsNonRoot`, usuario 65532 y seccomp `RuntimeDefault`. La prueba de humo respondió `{"version":"20.3.0"}`.

**Integración y publicación:** el PR #1 integró la rama en `master` sin conflictos. La ejecución sobre `master` repitió los 7 controles, el gate, las pruebas y el despliegue, todos en verde, y solo entonces publicó la imagen `ghcr.io/stevencedor/juice-shop-devsecops/juice-shop:85b1ad0ee6287c6bc3a677627bc48c529b5aac88`. La etiqueta es el SHA del commit, lo que permite rastrear la imagen hasta el código y los reportes exactos que la liberaron. En la rama de trabajo el job de publicación queda omitido por diseño: solo la rama por defecto publica.

**Conteo por severidad (hallazgos que reportan las herramientas, antes de aplicar excepciones):**

| Fuente | Ejecución 1 · C / A / M / B | Ejecución 2 · C / A / M / B | Cambio |
|---|---|---|---|
| Gitleaks | — / 225 / — / — | — / 225 / — / — | Igual: el historial git no cambia |
| Semgrep | — / 3 / 17 / — | — / 2 / 17 / — | −1 alta (VULN-002 corregida) |
| Trivy SCA | 9 / 29 / 32 / 5 | 9 / 29 / 32 / 5 | Igual: dependencias aceptadas |
| Trivy imagen (CVE + secretos) | 9 / 30 / 52 / 11 | 9 / 30 / 52 / 11 | Igual: dependencias aceptadas |
| Trivy IaC | 12 / 13 / 4 / 22 | 12 / 13 / 3 / 21 | −1 media y −1 baja (VULN-005 y VULN-006 corregidas) |
| ZAP | — / 0 / 2 / 0 | — / 0 / 2 / 4 | +4 bajas informativas; no cambian la decisión |

C = crítica, A = alta, M = media, B = baja.

## 2. Hallazgos de la aplicación (formato VULN-nnn)

### VULN-001 · Clave privada RSA de firma JWT en el repositorio y en la imagen
| Campo | Contenido |
|---|---|
| Severidad | **Crítica** |
| Control que lo detectó | Gitleaks (`private-key`, historial) y Trivy imagen (`private-key`, capas) |
| Activo afectado | `lib/insecurity.ts:21`, compilado en `/juice-shop/build/lib/insecurity.js:55`; histórico `lib/insecurity.js` (2017) |
| Amenaza Act. 2 | ST-23 Secretos expuestos (6) · ST-02 Falsificación de JWT (9) · habilita ST-18 |
| Descripción | La clave con la que el servidor firma los JWT está en texto plano en el código fuente y viaja dentro de la imagen desplegada. |
| Evidencia | `reports-secrets/gitleaks.json`, `reports-container/trivy-image.json` (Secrets) |
| Impacto | Cualquiera con acceso al código o a la imagen puede firmar un token con rol administrador (toma total de la aplicación). |
| Remediación | Rotar la clave, retirarla del historial, cargarla desde un gestor de secretos en tiempo de ejecución (ADR-SEC-001) y usar `kid` con rotación (C-03, C-04). |
| Criterio de cierre | Gitleaks y Trivy imagen sin `private-key` sin necesidad de excepción; un token firmado con la clave anterior es rechazado. |
| Decisión | **Aceptar con excepción** (secreto intencional del reto). Vence 2027-01-31. |
| Responsable | Carlos Bernal (Seguridad) |

### VULN-002 · Inyección SQL en el inicio de sesión — CORREGIDO
| Campo | Contenido |
|---|---|
| Severidad | **Crítica** |
| Control que lo detectó | Semgrep · `express-sequelize-injection` (ERROR) |
| Activo afectado | `routes/login.ts:34`, `POST /rest/user/login` |
| Amenaza Act. 2 | ST-01 Bypass de login por inyección SQL (9) |
| Descripción | El correo y la contraseña se concatenaban en la consulta SQL. Con `' OR 1=1--` en el correo se obtiene la sesión del primer usuario (administrador). |
| Evidencia | `reports-sast/semgrep.json` (ejecución 1) |
| Impacto | Toma de cuentas, incluida la administrativa, sin credenciales. |
| Remediación aplicada | Consulta parametrizada con `bind` (`$1`, `$2`), idéntica a la corrección oficial `data/static/codefixes/loginAdminChallenge_4_correct.ts`. |
| Criterio de cierre | Semgrep sin el hallazgo en la ejecución 2 sin excepción; pruebas unitarias del servidor en verde. **Cumplido:** en la ejecución 2 Semgrep ya no reporta `routes/login.ts` y el job de pruebas terminó en verde. |
| Decisión | **Corregir** (commit de remediación del triaje 1). |
| Responsable | Kevin Morales (Desarrollador) |

### VULN-003 · Inyección SQL UNION en la búsqueda de productos
| Campo | Contenido |
|---|---|
| Severidad | **Crítica** |
| Control que lo detectó | Semgrep · `express-sequelize-injection` (ERROR) |
| Activo afectado | `routes/search.ts:23`, `GET /rest/products/search?q=` |
| Amenaza Act. 2 | ST-06 Extracción SQL desde búsqueda (9) |
| Descripción | El criterio de búsqueda se interpola en la consulta; un `UNION SELECT` devuelve filas de la tabla de usuarios. |
| Evidencia | `reports-sast/semgrep.json` |
| Impacto | Fuga masiva de correos y hashes de contraseña (enlaza con ST-04). |
| Remediación | Misma técnica que VULN-002: consulta parametrizada y validación de longitud en servidor. |
| Criterio de cierre | Semgrep sin hallazgo y prueba de regresión con `'))UNION SELECT` que no altera la consulta. |
| Decisión | **Aceptar con excepción** (reto intencional `unionSqlInjection`). Vence 2027-01-31. |
| Responsable | Kevin Morales (Desarrollador) |

### VULN-004 · `jsonwebtoken` 0.4.0 permite saltar la verificación de firma
| Campo | Contenido |
|---|---|
| Severidad | **Crítica** · CVSS 9.8 (NVD) |
| Control que lo detectó | Trivy SCA y Trivy imagen · `CVE-2015-9235` |
| Activo afectado | `jsonwebtoken@0.4.0` y `@0.1.0` (dependencia directa y transitiva de `express-jwt@0.1.3`) |
| Amenaza Act. 2 | ST-02 Falsificación de JWT (9) · ST-22 Compromiso de dependencia (3) |
| Descripción | Versiones antiguas aceptan tokens con algoritmo alterado (`none` o confusión HS/RS). Es la misma familia de los 14 paquetes vulnerables aceptados (crypto-js 9.1, lodash 9.1, tar, decompress…). |
| Evidencia | `reports-sca/trivy-sca.json`, `reports-container/trivy-image.json` |
| Impacto | Suplantación de cualquier usuario sin conocer la clave. |
| Remediación | Actualizar a `jsonwebtoken` ≥ 9 y `express-jwt` ≥ 8 con algoritmos explícitos; para transitivas, `overrides` de npm y pruebas de regresión. |
| Criterio de cierre | QG-03 y QG-04 sin críticas ni altas con parche, sin excepciones de paquete. |
| Decisión | **Aceptar con excepción** (fijadas a propósito para los retos de JWT; transitivas en backlog). Vence 2027-01-31. |
| Responsable | Carlos Bernal (Líder técnico) |

### VULN-005 · Imagen base sin versión fija (`:latest` implícito) — CORREGIDO
| Campo | Contenido |
|---|---|
| Severidad | Media |
| Control que lo detectó | Trivy IaC · `DS-0001` |
| Activo afectado | `Dockerfile`, etapa final `FROM gcr.io/distroless/nodejs24-debian13` |
| Amenaza Act. 2 | ST-22 Compromiso de dependencia (cadena de suministro) |
| Descripción | Sin etiqueta ni digest, cada build puede traer una imagen base distinta, sin trazabilidad. |
| Remediación aplicada | `FROM ...:nonroot@sha256:cb606325…` (etiqueta explícita y digest inmutable). |
| Criterio de cierre | Trivy IaC sin `DS-0001` en la ejecución 2. **Cumplido.** |
| Decisión | **Corregir** |
| Responsable | Rafael Pachon (DevOps) |

### VULN-006 · Dockerfile sin chequeo de salud — CORREGIDO
| Campo | Contenido |
|---|---|
| Severidad | Baja |
| Control que lo detectó | Trivy IaC · `DS-0026` |
| Activo afectado | `Dockerfile` |
| Amenaza Act. 2 | ST-07 / ST-17 (disponibilidad): un contenedor colgado no se detecta |
| Remediación aplicada | `HEALTHCHECK` con el binario de Node de la imagen distroless (no tiene `curl` ni `sh`). |
| Criterio de cierre | Trivy IaC sin `DS-0026` en la ejecución 2. **Cumplido.** |
| Decisión | **Corregir** |
| Responsable | Rafael Pachon (DevOps) |

### VULN-007 · FALSO POSITIVO · "API keys" que son identificadores públicos
| Campo | Contenido |
|---|---|
| Severidad | Reportada Alta → real: no aplica |
| Control que lo detectó | Gitleaks · `generic-api-key` |
| Activo afectado | `frontend/src/app/manage-passkeys/passkey-providers.ts` (borrado en el historial) y `frontend/src/app/faucet/faucet.component.ts` |
| Razón técnica verificable | El primero contiene **AAGUID** públicos de proveedores de passkeys (lista pública `passkey-authenticator-aaguids`); el segundo, la **dirección pública de un contrato Ethereum**. Ninguno autentica a nadie (4 hallazgos). Se suman 196 hallazgos en `test/`, `cypress/` y `*.spec.ts`: tokens de ejemplo de pruebas. |
| Cómo se distinguió | Se abrió cada archivo en el commit reportado y se verificó el formato (UUID / dirección 0x de 40 hex) y su uso. |
| Decisión | **Falso positivo** con excepción acotada por ruta (no se silencia la regla en el resto del repositorio). |
| Responsable | Carlos Bernal (Seguridad) |

### VULN-008 · FALSO POSITIVO · Terraform inseguro que no se despliega
| Campo | Contenido |
|---|---|
| Severidad | Reportada Crítica (24 hallazgos: HTTP plano, egress abierto, EFS sin cifrar…) → real: no aplica |
| Control que lo detectó | Trivy IaC · `AWS-0054`, `AWS-0104`, `AWS-0037`… |
| Activo afectado | `data/static/codefixes/iacLeakedKeyChallenge_*.tf` |
| Razón técnica verificable | Son fragmentos que la aplicación **muestra como opciones de un reto de código**; no se aplican a ninguna nube. La infraestructura real es `k8s/` y `Dockerfile`. |
| Decisión | **Falso positivo de alcance** (excepción por ruta). Mejora propuesta: excluir la carpeta en el escaneo IaC, como ya hace Semgrep. |
| Responsable | Rafael Pachon (DevOps) |

### VULN-009 · Sistema de archivos del contenedor con escritura
| Campo | Contenido |
|---|---|
| Severidad | Alta |
| Control que lo detectó | Trivy IaC · `KSV-0014` |
| Activo afectado | `k8s/deployment.yaml` (`readOnlyRootFilesystem: false`) |
| Amenaza Act. 2 | ST-15 / ST-16 (amplía el impacto de un archivo malicioso o un recorrido de directorios) |
| Descripción | Juice Shop escribe en `logs/`, `ftp/`, `data/` e `i18n/` al arrancar; con raíz de solo lectura el pod no inicia sin montajes adicionales. |
| Remediación | `readOnlyRootFilesystem: true` con volúmenes `emptyDir` por directorio, validado con la prueba de humo. |
| Controles compensatorios | Usuario no root (65532), `allowPrivilegeEscalation: false`, `capabilities: drop ALL`, seccomp `RuntimeDefault`, NetworkPolicy, namespace PSA *restricted*. |
| Decisión | **Aceptar con excepción**. Vence 2027-01-31. |
| Responsable | Rafael Pachon (DevOps) |

### VULN-010 · `marsdb` con inyección de comandos y sin parche
| Campo | Contenido |
|---|---|
| Severidad | **Crítica** · `GHSA-5mrr-rgp6-x4gr` |
| Control que lo detectó | Trivy SCA y Trivy imagen |
| Activo afectado | `marsdb@0.6.11` (base documental de reseñas) |
| Amenaza Act. 2 | ST-20 Manipulación de filtros NoSQL (6) · ST-22 |
| Descripción | No existe versión corregida: actualizar no es posible. |
| Remediación | Reemplazar por un almacén mantenido (p. ej. MongoDB con validación de operadores). |
| Decisión | **Aceptar con excepción** (componente del reto NoSQL). Vence 2027-01-31. |
| Responsable | Carlos Bernal (Líder técnico) |

### VULN-011 · Defensas contra XSS insuficientes (CSP ausente + `sanitize-html` vulnerable)
| Campo | Contenido |
|---|---|
| Severidad | Media |
| Control que lo detectó | ZAP baseline · plugin 10038 *CSP Header Not Set* y 10098 *Cross-Domain Misconfiguration*; Trivy SCA · `sanitize-html@1.4.2` (CVE-2022-25887, 7.5) |
| Activo afectado | Todas las respuestas de `http://localhost:3000/` |
| Amenaza Act. 2 | ST-19 XSS almacenado (9) · ST-24 |
| Descripción | Sin CSP, un script inyectado se ejecuta sin restricción; CORS con `*` permite leer respuestas desde cualquier origen. |
| Remediación | Cabecera `Content-Security-Policy` restrictiva (`default-src 'self'`), CORS con lista blanca y `sanitize-html` ≥ 2.12. |
| Decisión | **Advertir** (QG-07 media = advertencia; queda en backlog). |
| Responsable | Kevin Morales (Desarrollador) |

### VULN-012 · Ejecución de código con `eval` en el nombre de usuario (SSTI)
| Campo | Contenido |
|---|---|
| Severidad | **Crítica** |
| Control que lo detectó | Semgrep · `code-string-concat` |
| Activo afectado | `routes/userProfile.ts:65` |
| Amenaza Act. 2 | **No modelada.** Se propone agregar "ST-27 · Inyección de plantillas / RCE en perfil (E, P=2, I=3)". |
| Descripción | Un nombre con la forma `#{...}` se evalúa en el servidor. |
| Remediación | Eliminar `eval`; tratar el nombre como dato y codificarlo en la vista. |
| Decisión | **Aceptar con excepción** (reto SSTI). Vence 2027-01-31. |
| Responsable | Kevin Morales (Desarrollador) |

## 3. Hallazgos sobre el propio pipeline

| ID | Qué pasó | Causa | Corrección |
|---|---|---|---|
| P-01 | QG-07 bloqueó con "SIN EVIDENCIA" aunque ZAP sí produjo reporte | `upload-artifact` con dos rutas en carpetas distintas guardó `zap.json` dentro de `reports/` del artefacto | Copiar ambos archivos a `reports/` antes de subir. El gate funcionó como debía: sin evidencia no libera. **Verificado:** en la ejecución 2 QG-07 evaluó el reporte (0 altas, 2 medias). |
| P-02 | QG-04 no contó 3 claves privadas altas dentro de la imagen | Las reglas de severidad alta solo miraban CVE con o sin parche; un secreto no tiene versión y no coincidía con ninguna | Nuevo modo `fix: secret` en el evaluador, regla en QG-04 y prueba unitaria que lo reproduce. **Verificado:** en la ejecución 2 QG-04 evalúa la regla de secretos y los 5 secretos de la imagen quedan cubiertos por excepciones explícitas. |

## 4. Matriz de decisión

| Herramienta | Hallazgo | Severidad | Evidencia | Decisión | Responsable |
|---|---|---|---|---|---|
| Gitleaks / Trivy imagen | VULN-001 Clave JWT en código e imagen | Crítica | gitleaks.json, trivy-image.json | Aceptar (vence 2027-01-31) | Carlos Bernal |
| Semgrep | VULN-002 SQLi login | Crítica | semgrep.json | **Corregido** | Kevin Morales |
| Semgrep | VULN-003 SQLi búsqueda | Crítica | semgrep.json | Aceptar | Kevin Morales |
| Trivy SCA / imagen | VULN-004 jsonwebtoken y 13 paquetes más | Crítica | trivy-sca.json | Aceptar con plan | Carlos Bernal |
| Trivy IaC | VULN-005 Imagen `:latest` | Media | trivy-iac.json | **Corregido** | Rafael Pachon |
| Trivy IaC | VULN-006 Sin HEALTHCHECK | Baja | trivy-iac.json | **Corregido** | Rafael Pachon |
| Gitleaks | VULN-007 AAGUID / dirección pública / fixtures | No aplica | gitleaks.json | **Falso positivo** | Carlos Bernal |
| Trivy IaC | VULN-008 Terraform de retos | No aplica | trivy-iac.json | **Falso positivo** | Rafael Pachon |
| Trivy IaC | VULN-009 Raíz con escritura | Alta | trivy-iac.json | Aceptar | Rafael Pachon |
| Trivy SCA | VULN-010 marsdb sin parche | Crítica | trivy-sca.json | Aceptar | Carlos Bernal |
| ZAP / Trivy SCA | VULN-011 CSP ausente / sanitize-html | Media | zap.json | Advertir | Kevin Morales |
| Semgrep | VULN-012 eval SSTI | Crítica | semgrep.json | Aceptar | Kevin Morales |

## 5. Análisis

- **Tipos predominantes.** Dominan las dependencias vulnerables (ST-22: 75 CVE en SCA) y los secretos (ST-23: 225 en el historial). En código propio, las fallas altas son inyecciones (ST-01, ST-06) y ejecución dinámica (SSTI), coherentes con los riesgos 9/9 de la Actividad 2.
- **Defensa en profundidad.** La clave JWT (VULN-001) la detectaron dos controles distintos: Gitleaks en el repositorio y Trivy en la imagen. El segundo prueba que el secreto llega al artefacto desplegado, algo que el escaneo del repositorio no demuestra.
- **Qué no detectó el pipeline.** Ningún control automático vio IDOR (ST-09), la API administrativa sin rol (ST-18) ni la manipulación de precios (ST-08). Requieren pruebas de autorización y de lógica de negocio. La cobertura sigue siendo 12 de 26 amenazas.
- **Falsos positivos.** Representan la mayoría de los secretos (200 de 225); los 25 restantes son secretos intencionales del laboratorio o valores en archivos ya eliminados del historial. Se distinguieron revisando el formato y el uso del valor en el commit reportado, y se aceptaron solo por ruta, sin desactivar reglas globales.
- **Excepciones.** 50 entradas, cada una con justificación, responsable y vencimiento ≤ 180 días. El gate QG-08 bloquea si alguna vence o queda incompleta.
- **El gate también se audita.** El triaje encontró dos defectos del pipeline (P-01, P-02). P-02 era un punto ciego real: el umbral escrito ("0 secretos") no coincidía con la regla implementada.
- **Riesgo residual.** Sigue alto mientras la clave JWT y las dependencias de los retos permanezcan. En un sistema real, VULN-001 y VULN-004 serían bloqueantes sin excepción posible.

## 6. Conclusiones

El pipeline cumplió su función principal: detuvo una versión con fallas críticas y produjo evidencia trazable a los riesgos de la Actividad 2. El triaje convirtió 476 hallazgos de herramientas en 12 decisiones concretas: 3 correcciones, 2 falsos positivos, 6 riesgos aceptados con responsable y 1 advertencia. La remediación de VULN-002 muestra el ciclo completo: detección, corrección, verificación automática y liberación. Los siguientes pasos son pruebas de autorización automatizadas para ST-09/ST-18 y la gestión externa de secretos (ADR-SEC-001).

## Referencias (APA 7)
Aqua Security. (2026). *Trivy ecosystem supply chain temporarily compromised* (GHSA-69fq-xp46-6x23) [Aviso de seguridad]. GitHub. https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218

OWASP Foundation. (2021). *OWASP Application Security Verification Standard 4.0.3*. https://github.com/OWASP/ASVS/releases/tag/v4.0.3_release

OWASP Foundation. (s. f.). *CI/CD Security Cheat Sheet*. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html

OWASP Foundation. (2026). *OWASP Juice Shop*. https://owasp.org/www-project-juice-shop/

Samacá Piñeros, F. J. (2026). *Material de apoyo DevSecOps (Anexo 3)* [Material de apoyo de Seguridad en Software II].
