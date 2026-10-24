# Trazabilidad: riesgos de la Actividad 2 → controles del pipeline

**Sistema base:** OWASP Juice Shop (mismo sistema de las Actividades 1 y 2).
**Fuente de riesgos:** Matriz de riesgo priorizada, Tabla 5 de la Actividad 2 (P × I, escala 1–3; 22 riesgos altos, 4 medios).
**Regla de selección:** se automatizó primero lo que ataca riesgos de prioridad alta (≥ 6) detectables sin intervención humana.

## 1. Controles seleccionados y riesgo que justifica a cada uno

| Control | Herramienta | Etapa | Amenazas (Act. 2) | P×I | Cobertura | Por qué este control para este riesgo |
|---|---|---|---|---|---|---|
| C1 Secretos | Gitleaks | Pre-build | ST-23 Secretos expuestos en despliegue | 6 Alta | Directa | Detecta claves y credenciales en código e historial git (ADR-SEC-001). |
| | | | ST-02 Falsificación de JWT | 9 Alta | Parcial | Una clave de firma en el repositorio permite forjar tokens. |
| | | | ST-16 Recorrido de directorios y fuga de secretos | 9 Alta | Parcial | Evita que las claves estén donde un traversal las alcance. |
| C2 SAST | Semgrep | Pre-build | ST-01 Bypass de login por inyección SQL | 9 Alta | Directa | Reglas de inyección SQL sobre consultas construidas con entrada de usuario. |
| | | | ST-06 Extracción SQL desde búsqueda (UNION) | 9 Alta | Directa | Misma familia de reglas aplicada al buscador. |
| | | | ST-19 XSS almacenado en reseñas | 9 Alta | Parcial | Detecta sumideros sin codificación; no prueba el flujo completo. |
| | | | ST-15 Archivo malicioso / XXE | 6 Alta | Parcial | Reglas de parsers XML sin deshabilitar entidades. |
| | | | ST-16 Recorrido de directorios | 9 Alta | Parcial | Reglas de rutas armadas con entrada de usuario. |
| | | | ST-14 Escalada por mass assignment | 9 Alta | Parcial | Solo reglas genéricas de asignación masiva; la validación real requiere pruebas de API. |
| | | | ST-20 Manipulación masiva de filtros (NoSQL) | 6 Alta | Parcial | Operadores NoSQL aceptados sin validar. |
| C3 SCA | Trivy (fs) | Pre-build | ST-22 Compromiso de dependencia | 3 Media | Directa | Compara cada dependencia directa y transitiva con CVE conocidos. El riesgo es Media (P=1) pero el impacto es máximo. |
| | | | ST-02 Falsificación de JWT | 9 Alta | Parcial | Detecta versiones vulnerables de `jsonwebtoken`, `express-jwt` y `jws`, que facilitan aceptar tokens forjados. |
| C4 Contenedor | Trivy (imagen) | Build | ST-22 Compromiso de dependencia | 3 Media | Directa | Revisa lo que realmente se despliega (capas + paquetes del SO). |
| | | | ST-23 Secretos en imagen | 6 Alta | Directa | Busca secretos dentro de las capas. |
| C5 IaC | Trivy (config) | Pre-deploy | ST-23 Secretos/configuración | 6 Alta | Parcial | Manifiestos con secretos, root, sin límites o sin seccomp. |
| | | | ST-25 Intercepción de tráfico | 6 Alta | Parcial | Señala configuración sin TLS. |
| | | | ST-15 / ST-16 (impacto) | 6 / 9 | Mitigación de impacto | Un contenedor sin privilegios limita el alcance de una explotación (ADR-SEC-001). |
| C6 SBOM | Syft (CycloneDX) | Build | ST-22 Compromiso de dependencia | 3 Media | Directa | Inventario para responder rápido ante un CVE nuevo y demostrar trazabilidad. |
| C7 DAST | OWASP ZAP baseline | Post-build | ST-24 Divulgación en mensajes de error | 6 Alta | Parcial | Detecta divulgación de versiones y trazas en la app en ejecución. |
| | | | ST-25 Intercepción de tráfico | 6 Alta | Parcial | Detecta ausencia de HSTS y cabeceras de seguridad. |

## 2. Cobertura global de las 26 amenazas

- **Cubiertas (directa o parcialmente): 12 de 26** → ST-01, ST-02, ST-06, ST-15, ST-16, ST-19, ST-20, ST-22, ST-23, ST-24, ST-25 y ST-14 (parcial: asignación masiva solo se detecta por reglas genéricas).
- **Altas cubiertas: 11 de 22.**
- **No cubiertas por automatización (declaradas como riesgo residual):**

| Amenaza | Por qué el pipeline no la cubre | Control recomendado (siguiente iteración) |
|---|---|---|
| ST-09 IDOR/BOLA (9), ST-18 API administrativa sin rol (9) | Son fallas de lógica de autorización; un baseline pasivo no las ve | Pruebas de autorización automatizadas (ADR-SEC-002) con credenciales de dos usuarios |
| ST-05 Credential stuffing (9), ST-07, ST-17 | Requieren pruebas de carga/rate limit | Prueba de límite de tasa en CI |
| ST-08, ST-10, ST-13, ST-21 | Lógica de negocio | Pruebas de API con casos abusivos |
| ST-03, ST-04, ST-11, ST-12, ST-26 | Diseño y operación (recuperación, hashing, auditoría) | Revisión de diseño y ADR-SEC-003 (auditoría inmutable) |

## 3. Alineación con las decisiones de arquitectura (Act. 2, §6)

| ADR | Qué verifica el pipeline | Qué queda fuera |
|---|---|---|
| ADR-SEC-001 Separar secretos y archivos servidos | C1, C4 (secretos), C5 (usuario no root, sin secretos en manifiestos) | Gestor de secretos externo y rotación |
| ADR-SEC-002 Autorización centralizada | Nada directo (ver tabla anterior) | Todo |
| ADR-SEC-003 Auditoría inmutable | La evidencia de cada ejecución (artefactos, SBOM, decisión del gate) deja rastro de liberación | Auditoría de la aplicación |

> Nota metodológica: ASVS 4.0.3, como en la Actividad 2, para mantener la trazabilidad.
