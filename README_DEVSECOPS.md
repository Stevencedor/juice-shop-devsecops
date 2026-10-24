# Pipeline DevSecOps sobre OWASP Juice Shop

Actividad 3 · Seguridad en Software II · Universidad de La Salle.
Sistema base: **OWASP Juice Shop** (Actividades 1 y 2). Aplicación Node.js/Express + Angular; imagen Docker; despliegue en Kubernetes.

## Qué hace
Cada `push` a `master`/`main`/`feature/**` y cada pull request ejecuta 7 controles automatizados, los evalúa contra umbrales (`security/quality-gates.yml`) y solo si el **Quality Gate** libera despliega en un clúster kind efímero y publica la imagen.

| Control | Herramienta | Amenazas Act. 2 |
|---|---|---|
| C1 Secretos | Gitleaks | ST-23, ST-02, ST-16 |
| C2 SAST | Semgrep | ST-01, ST-06, ST-19, ST-15, ST-16, ST-20, ST-14 (parcial) |
| C3 SCA | Trivy (fs) | ST-22, ST-02 (parcial) |
| C4 Contenedor | Trivy (imagen) | ST-22, ST-23 |
| C5 IaC | Trivy (config) | ST-23, ST-25 |
| C6 SBOM | Syft (CycloneDX) | ST-22 |
| C7 DAST | OWASP ZAP baseline | ST-24, ST-25 |

Además, el job **Test** ejecuta las pruebas unitarias del servidor y del evaluador de gates; el despliegue exige que pasen.

Detalle y cobertura (12/26 amenazas): `docs/01_trazabilidad_riesgos.md`. Diagrama: `docs/05_diagrama_pipeline.md`.

## Estructura
```
.github/workflows/devsecops.yml   pipeline (acciones fijadas por SHA, sin secretos externos)
security/quality-gates.yml        política: umbral + acción por control
security/exceptions.yml           riesgo aceptado (responsable, justificación, vencimiento ≤180 días)
scripts/quality_gate.py           evaluador (pruebas: python -m unittest discover -s scripts/tests)
k8s/                              namespace (PSA restricted), deployment, service, networkpolicy
docs/                             trazabilidad, quality gates (xlsx), plantilla de reporte, guion de video
```

## Cómo se decide
- **Bloquear:** secretos > 0; SAST/ZAP alto > 0; CVE crítica > 0; CVE alta con parche > 0; IaC crítico/alto > 0; SBOM ausente; reporte ausente; excepción vencida o incompleta.
- **Advertir:** severidad media; CVE alta sin parche.
- **Permitir:** solo con excepción registrada, vigente y con responsable.

## Ejecutar localmente (opcional)
```bash
docker build -t juice-shop:local .
docker run --rm -p 3000:3000 juice-shop:local      # http://localhost:3000
python -m venv .venv && . .venv/bin/activate && pip install pyyaml
python -m unittest discover -s scripts/tests -v
```

## Advertencia
Juice Shop es **deliberadamente vulnerable**. Se despliega solo en un clúster efímero sin datos reales y con NetworkPolicy restrictiva. No exponerlo a Internet.
