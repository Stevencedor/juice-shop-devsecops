# Resultado del Quality Gate - 2026-10-24

**Decisión global: ⚠️ WARN**

| Gate | Control | Herramienta | Resultado | Detalle |
|---|---|---|---|---|
| QG-01 | Secretos | gitleaks | ✅ PASS | CRITICAL/HIGH/MEDIUM/LOW: 0 (máximo 0) -> ok<br>225 hallazgos cubiertos por excepciones vigentes |
| QG-02 | SAST | semgrep | ⚠️ WARN | CRITICAL/HIGH: 0 (máximo 0) -> ok<br>MEDIUM: 17 (máximo 0) -> WARN<br>2 hallazgos cubiertos por excepciones vigentes |
| QG-03 | SCA | trivy-sca | ⚠️ WARN | CRITICAL: 0 (máximo 0) -> ok<br>HIGH (fixed): 0 (máximo 0) -> ok<br>HIGH (unfixed): 0 (máximo 0) -> ok<br>MEDIUM: 5 (máximo 0) -> WARN<br>67 hallazgos cubiertos por excepciones vigentes |
| QG-04 | Contenedor | trivy-image | ⚠️ WARN | CRITICAL/HIGH/MEDIUM/LOW (secret): 0 (máximo 0) -> ok<br>CRITICAL: 0 (máximo 0) -> ok<br>HIGH (fixed): 0 (máximo 0) -> ok<br>HIGH (unfixed): 0 (máximo 0) -> ok<br>MEDIUM: 28 (máximo 0) -> WARN<br>64 hallazgos cubiertos por excepciones vigentes |
| QG-05 | IaC / configuración | trivy-iac | ✅ PASS | CRITICAL/HIGH: 0 (máximo 0) -> ok<br>MEDIUM: 0 (máximo 0) -> ok<br>49 hallazgos cubiertos por excepciones vigentes |
| QG-06 | SBOM | sbom | ✅ PASS | 2744 componentes en el SBOM (mínimo 1) |
| QG-07 | DAST | zap | ⚠️ WARN | CRITICAL/HIGH: 0 (máximo 0) -> ok<br>MEDIUM: 2 (máximo 0) -> WARN |
| QG-08 | Gobierno de excepciones | exceptions | ✅ PASS | todas las excepciones son válidas (o no hay excepciones) |
