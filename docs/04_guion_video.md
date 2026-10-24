# Guion del video (objetivo 7 min; permitido 5–8)

Regla: mostrar la pantalla, hablar sobre lo que se ve, y no leer diapositivas. Grabar con pestañas ya abiertas.

| Min | Qué mostrar | Qué decir |
|---|---|---|
| 0:00–0:45 | Portada + `docs/01_trazabilidad_riesgos.md` | Sistema (Juice Shop), integrantes, objetivo. Riesgos más altos de la Act. 2 (ST-01, ST-02, ST-16, ST-19…) que motivan el pipeline. |
| 0:45–2:00 | Diagrama (`docs/05_diagrama_pipeline.md`) | Etapas: secretos → SAST/SCA/IaC → imagen+SBOM → DAST → quality gate → deploy K8s → publicar. Por qué cada control (una frase con ST-nn). Sin secretos externos y acciones fijadas por SHA. |
| 2:00–3:15 | `security/quality-gates.yml` y el xlsx | Umbral, severidad y acción (bloquear/advertir/permitir). Excepciones con dueño y vencimiento (máx. 180 días). |
| 3:15–5:00 | **Ejecución 1** (roja): pestaña Actions + resumen del gate | Por qué se bloquea. Abrir 2–3 hallazgos reales (secreto en `lib/insecurity.ts`, CVE crítica, regla Semgrep). Qué severidad y amenaza representan. |
| 5:00–6:15 | Triaje: `exceptions-suggested.yml` → `exceptions.yml`, y una corrección real | Distinguir corregir / aceptar / falso positivo. Mostrar un commit de remediación. |
| 6:15–7:15 | **Ejecución 2** (verde) + job Deploy K8s + smoke test + SBOM | Gate liberado, despliegue en kind, `kubectl get pods`, evidencias descargables. |
| 7:15–7:45 | Cobertura y límites | 12/26 amenazas cubiertas; ST-09/ST-18 requieren pruebas de autorización (riesgo residual). Cierre. |
