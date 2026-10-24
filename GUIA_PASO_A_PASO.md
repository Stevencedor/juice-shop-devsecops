# Guía paso a paso (Camino A: fork de Juice Shop en GitHub)

Tiempo estimado: 1 tarde para tener la ejecución 1; 1 tarde de triaje y ejecución 2; 1 tarde de reporte y video.
Reparto sugerido: **A** pipeline y ejecuciones · **B** triaje, excepciones y reporte · **C** trazabilidad, xlsx y video.

## Paso 1 · Fork y limpieza
1. En GitHub: abra https://github.com/juice-shop/juice-shop → **Fork** → cuenta o la organización del grupo. Nombre sugerido: `juice-shop-devsecops`. Agregue a sus compañeros y al profesor como colaboradores (Settings → Collaborators).
2. En la pestaña **Actions** del fork, pulse *I understand my workflows, go ahead and enable them*.
3. Clone y cree la rama de trabajo (la rama por defecto de Juice Shop es `master`):
```bash
git clone https://github.com/<usuario>/juice-shop-devsecops.git
cd juice-shop-devsecops
git checkout -b feature/devsecops-pipeline
git rm -q .github/workflows/*.yml     # los workflows originales (heroku, release, etc.) fallarían en el fork
```

## Paso 2 · Aplicar el kit
```bash
unzip ../devsecops-kit.zip -d /tmp/kit
cp -r /tmp/kit/devsecops-kit/{.github,security,scripts,k8s,docs} .
cp /tmp/kit/devsecops-kit/README_DEVSECOPS.md .
git add -A && git commit -m "feat: pipeline DevSecOps (7 controles, quality gates, k8s)"
```
Antes de subir, edite `security/exceptions.yml` si quiere (por ahora vacío: **así la primera ejecución debe fallar**).

## Paso 3 · Ejecución 1 (evidencia de bloqueo)
```bash
git push -u origin feature/devsecops-pipeline
```
En **Actions** verá el workflow *DevSecOps Pipeline*. Tarda ~20–30 min (el build de Juice Shop es lento). Lo esperado: los jobs de análisis terminan en verde (los scanners no bloquean por sí solos) y **Quality Gate** en rojo. Esta guía no se pudo ejecutar contra GitHub desde aquí: si una acción de terceros cambió algún parámetro, el error aparecerá en la primera ejecución y se corrige en el YAML.
Guarde como evidencia (carpeta `evidencias/ejecucion1/`):
- Captura del grafo de jobs y del **Summary** de Quality Gate (tabla con ⛔).
- Descargue los artefactos: `reports-*`, `quality-gate-result`.
Si un job de análisis falla en rojo (no el gate), vaya a *Solución de problemas*.

**Lo que se espera encontrar** (verificado de forma previa, no es el resultado oficial): `npm audit` sobre las dependencias de Juice Shop reporta 9 críticas y 18 altas (p. ej. `jsonwebtoken`, `lodash`, `crypto-js`, `handlebars`, `hbs`, `decompress`, `marsdb`, `pdfkit`), y `lib/insecurity.ts` contiene una clave privada RSA en texto plano. Eso alimenta ST-22, ST-23 y ST-02.

## Paso 4 · Triaje (el paso que más puntúa en «interpretación de hallazgos»)
Abra `quality-gate-result` → `exceptions-suggested.yml`. Cada grupo es un hallazgo a decidir. Para cada uno elija **una** de tres salidas:

| Decisión | Cuándo | Qué se hace |
|---|---|---|
| **Corregir** | El defecto está en lo que *nosotros* controlamos (Dockerfile, `k8s/`, pipeline, una dependencia actualizable) | Commit con la corrección. No va en exceptions. |
| **Aceptar con excepción** | Vulnerabilidad *intencional* del laboratorio (retos de Juice Shop) o sin parche disponible | Copiar el grupo a `security/exceptions.yml` con `justification` (por qué + controles compensatorios: kind efímero, sin datos reales, NetworkPolicy), `owner` (nombre real) y `expires` (≤ 180 días). |
| **Falso positivo** | La herramienta se equivoca | Excepción con la razón técnica verificable. |

Reglas del gate: una excepción con `TODO`, sin dueño, vencida o de más de 180 días **bloquea** (QG-08). `id: '*'` solo se admite junto con `package` o `path`.

**Corrija al menos 2 hallazgos reales** para demostrar remediación. Opciones seguras:
1. *Dockerfile:* agregar `HEALTHCHECK` (hallazgo típico de IaC). Ejemplo para la imagen distroless:
```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD ["/nodejs/bin/node","-e","require('http').get('http://localhost:3000/rest/admin/application-version',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]
```
2. *k8s:* `readOnlyRootFilesystem: true` + `emptyDir` en `/juice-shop/logs`, `/juice-shop/ftp` y `/juice-shop/data` (pruebe localmente que la app arranca; si no, déjelo como excepción documentada).
3. *Dependencias:* actualizar una dependencia **no usada por un reto** (revise `package.json`; muchas están fijadas a propósito).
Elija 2 con plan de remediación completo para el reporte (formato VULN-nnn de `docs/03_reporte_hallazgos_plantilla.md`) y un falso positivo si lo hay.

## Paso 5 · Ejecución 2 (evidencia de liberación)
```bash
git add -A && git commit -m "fix: remediaciones y excepciones aprobadas (triaje 1)" && git push
```
Repita hasta que **Quality Gate** quede en ✅ (puede haber ⚠️: son advertencias legítimas y se reportan). Entonces corren *Deploy K8s (kind)* y el smoke test. Guarde capturas y el artefacto `deploy-evidence` (salida de `kubectl get pods`).
Después abra un Pull Request **en su fork** (¡cuidado! GitHub propone por defecto el repositorio original `juice-shop/juice-shop`: cambie *base repository* a su fork) y haga merge a `master`: se ejecuta de nuevo y publica la imagen en GHCR (Packages).

## Paso 6 · Entregables
1. `docs/02_quality_gates.xlsx` ya está generado desde la política. Si cambia umbrales: `pip install pyyaml openpyxl && python scripts/export_gates_xlsx.py`.
2. `docs/03_reporte_hallazgos_plantilla.md` → copiar a `docs/03_reporte_hallazgos.md` y completar con los datos reales (resumen ejecución 1 vs 2, ≥ 6 hallazgos, matriz de decisión, análisis, referencias APA 7). Puede entregarse como PDF o Word.
3. Trazabilidad: `docs/01_trazabilidad_riesgos.md` (ya hecha; revise que sus IDs coincidan con su PDF de la Actividad 2).
4. Video: seguir `docs/04_guion_video.md` (5–8 min).
5. `docs/06_checklist_entrega.md`: marcar todo y `git tag entrega-act3 && git push --tags`.

## Solución de problemas
| Síntoma | Causa probable | Solución |
|---|---|---|
| El workflow no aparece | Actions deshabilitadas en el fork | Pestaña Actions → habilitar |
| `secret-scan` falla con «dubious ownership» | Contenedor sin acceso al repo | Ya se pasa `safe.directory`; revise que el checkout use `fetch-depth: 0` |
| `sca` no encuentra dependencias | Sin lockfile | El job lo genera; si `npm install --package-lock-only` falla en `frontend`, mantenga `--legacy-peer-deps` |
| `container` falla en el build | El build de Juice Shop es pesado y lento | Reintentar; revisar el log del paso «Build de la imagen» |
| `dast` no encuentra `report_json.json` | ZAP no pudo llegar a la app | Revise el paso «Cargar y ejecutar la imagen» (espera hasta 3 min) |
| `Quality Gate` dice «SIN EVIDENCIA» | Un job previo no subió su reporte | Abra ese job; sin reporte no hay liberación (es intencional) |
| `deploy-k8s` falla con ImagePullBackOff | La imagen no se cargó en kind | Verifique el paso `kind load docker-image` |
| El pod no arranca por PSA | `namespace` exige perfil *restricted* | Revise `securityContext` en `k8s/deployment.yaml` |

## Cosas que NO debe hacer
- Fijar el gate en `continue-on-error` para «que pase»: invalida la evidencia.
- Aceptar excepciones masivas sin justificación individual: baja la nota de «interpretación».
- Exponer el despliegue de Juice Shop fuera del clúster efímero.
- Subir secretos propios al repositorio (Gitleaks también los verá).
