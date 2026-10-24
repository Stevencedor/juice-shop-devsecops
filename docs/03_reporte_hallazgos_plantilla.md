# Reporte consolidado de hallazgos — Pipeline DevSecOps sobre OWASP Juice Shop

**Ejecución analizada:** <enlace a la ejecución de GitHub Actions> · **Commit:** `<sha>` · **Fecha:** <AAAA-MM-DD>
**Ambiente:** laboratorio (GitHub Actions + kind efímero, sin datos reales).

## 1. Resumen ejecutivo
| Control | Gate | Resultado ejecución 1 (código original) | Resultado ejecución 2 (tras triaje) |
|---|---|---|---|
| Secretos | QG-01 | ⛔ N hallazgos | ✅ / ⚠️ |
| SAST | QG-02 | | |
| SCA | QG-03 | | |
| Contenedor | QG-04 | | |
| IaC | QG-05 | | |
| SBOM | QG-06 | | |
| DAST | QG-07 | | |
| Excepciones | QG-08 | | |

Conteo por severidad (alta/media/baja) y decisión global: <completar con gate-summary.md>.

## 2. Hallazgos (mínimo 6; formato VULN-nnn del Anexo 3)
Copiar el bloque por cada hallazgo seleccionado. Elegir al menos: un secreto, un SAST, un SCA, uno de IaC/contenedor, un DAST y **un falso positivo**.

### VULN-001 · <título>
| Campo | Contenido |
|---|---|
| Severidad | Crítica / Alta / Media / Baja (CVSS si aplica) |
| Control que lo detectó | Gitleaks / Semgrep / Trivy / ZAP · regla o CVE: `<id>` |
| Activo afectado | archivo:línea, paquete@versión o endpoint |
| Amenaza Act. 2 | ST-nn (P×I) |
| Descripción | Qué ocurre y por qué es un problema |
| Evidencia | Fragmento del reporte, captura, enlace al artefacto `reports/...json` |
| Impacto técnico y de negocio | |
| Remediación | Acción concreta y verificable |
| Criterio de cierre | Cómo se comprueba que quedó corregido (p. ej., el gate pasa sin la excepción) |
| Decisión | Corregir / Aceptar con excepción (ticket, responsable, vencimiento) / Falso positivo (razón técnica) |
| Responsable | |

## 3. Matriz de decisión (herramienta, hallazgo, severidad, evidencia, decisión, responsable)
| Herramienta | Hallazgo | Severidad | Evidencia | Decisión | Responsable |
|---|---|---|---|---|---|

## 4. Análisis
- **Tipos de vulnerabilidad predominantes** y a qué amenazas de la Actividad 2 corresponden.
- **Qué detectó el pipeline y qué no** (ver cobertura 12/26 en la trazabilidad).
- **Falsos positivos** y cómo se distinguieron.
- **Excepciones aceptadas:** cuántas, por qué, quién responde y cuándo vencen.
- **Riesgo residual** y siguientes pasos.

## 5. Conclusiones
<3–5 líneas>

## Referencias (APA 7)
Aqua Security. (2026). *Trivy ecosystem supply chain temporarily compromised* (GHSA-69fq-xp46-6x23) [Aviso de seguridad]. GitHub. https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218

OWASP Foundation. (2021). *OWASP Application Security Verification Standard 4.0.3*. https://github.com/OWASP/ASVS/releases/tag/v4.0.3_release

OWASP Foundation. (s. f.). *CI/CD Security Cheat Sheet*. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html

Samacá Piñeros, F. J. (2026). *Material de apoyo DevSecOps (Anexo 3)* [Material de apoyo de Seguridad en Software II].
