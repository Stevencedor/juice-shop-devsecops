#!/usr/bin/env python3
"""Evalúa los quality gates de security/quality-gates.yml contra los reportes
JSON de los scanners, aplica security/exceptions.yml y decide si se libera.

Salida: 0 = libera (puede haber advertencias) | 1 = bloqueado.
Un reporte ausente o ilegible BLOQUEA: sin evidencia no hay liberación.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import yaml

SEVS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEMGREP_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
ZAP_MAP = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
MAX_EXCEPTION_DAYS = 180
RANK = {"PASS": 0, "WARN": 1, "BLOCK": 2}
ICON = {"PASS": "✅ PASS", "WARN": "⚠️ WARN", "BLOCK": "⛔ BLOCK"}


class ReportError(Exception):
    pass


@dataclass
class Finding:
    tool: str
    rule: str
    severity: str
    title: str
    location: str
    path: str = ""
    package: str = ""
    fixed: bool | None = None


# ----------------------------------------------------------------- parsers
def load_json(path: Path):
    if not path.is_file():
        raise ReportError(f"no existe el reporte {path.name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReportError(f"JSON inválido en {path.name}: {exc}") from exc


def sev(value: str, default: str = "INFO") -> str:
    value = str(value or "").upper()
    return value if value in SEVS else default


def parse_gitleaks(data, tool):
    out = []
    for f in data or []:
        path = f.get("File", "")
        out.append(Finding(tool, f.get("RuleID", "?"), "HIGH", f.get("Description", ""),
                           f"{path}:{f.get('StartLine', '?')}", path))
    return out


def parse_semgrep(data, tool):
    out = []
    for r in (data or {}).get("results", []):
        extra = r.get("extra", {})
        raw = str(extra.get("severity", "")).upper()
        severity = SEMGREP_MAP.get(raw) or sev(raw, "MEDIUM")
        path = r.get("path", "")
        out.append(Finding(tool, r.get("check_id", "?"), severity,
                           (extra.get("message") or "")[:160],
                           f"{path}:{r.get('start', {}).get('line', '?')}", path))
    return out


def parse_trivy(data, tool):
    out = []
    for res in (data or {}).get("Results") or []:
        target = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            out.append(Finding(tool, v.get("VulnerabilityID", "?"), sev(v.get("Severity")),
                               f"{v.get('PkgName', '')} {v.get('InstalledVersion', '')} - {v.get('Title', '')}"[:160],
                               target, target, v.get("PkgName", ""), bool(v.get("FixedVersion"))))
        for m in res.get("Misconfigurations") or []:
            if str(m.get("Status", "FAIL")).upper() != "FAIL":
                continue
            out.append(Finding(tool, m.get("ID") or m.get("AVDID", "?"), sev(m.get("Severity")),
                               m.get("Title", ""), target, target))
        for s in res.get("Secrets") or []:
            out.append(Finding(tool, s.get("RuleID", "?"), sev(s.get("Severity"), "HIGH"),
                               s.get("Title", "secreto"), f"{target}:{s.get('StartLine', '?')}", target))
    return out


def parse_zap(data, tool):
    out = []
    for site in (data or {}).get("site", []):
        for a in site.get("alerts", []):
            inst = (a.get("instances") or [{}])[0]
            uri = inst.get("uri", "")
            out.append(Finding(tool, str(a.get("pluginid", "?")), ZAP_MAP.get(str(a.get("riskcode")), "INFO"),
                               a.get("alert") or a.get("name", ""), uri, uri))
    return out


PARSERS = {"gitleaks": parse_gitleaks, "semgrep": parse_semgrep, "trivy": parse_trivy, "zap": parse_zap}


# -------------------------------------------------------------- exceptions
def norm_id(value: str) -> str:
    """KSV-0014, AVD-KSV-0014 y KSV014 se consideran el mismo identificador."""
    s = re.sub(r"^AVD-", "", str(value).strip().upper())
    m = re.fullmatch(r"([A-Z]+)[-_]?0*(\d+)", s)
    return f"{m.group(1)}{int(m.group(2))}" if m else s


def parse_date(value) -> dt.date | None:
    if isinstance(value, dt.date):
        return value
    try:
        return dt.date.fromisoformat(str(value).strip())
    except ValueError:
        return None


def load_exceptions(path: Path, today: dt.date):
    if not path.is_file():
        return [], []
    items = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("exceptions") or []
    valid, invalid = [], []
    for e in items:
        problems = [f"falta {k}" for k in ("tool", "id", "justification", "owner", "expires")
                    if not str(e.get(k, "")).strip()]
        if "todo" in str(e.get("justification", "")).lower() or "todo" in str(e.get("owner", "")).lower():
            problems.append("justificación/responsable pendiente (TODO)")
        if str(e.get("id", "")).strip() == "*" and not (e.get("package") or e.get("path")):
            problems.append("id '*' solo se permite junto con package o path")
        exp = parse_date(e.get("expires"))
        if "expires" not in " ".join(problems) and not exp:
            problems.append("fecha de vencimiento inválida")
        elif exp and exp < today:
            problems.append(f"vencida el {exp}")
        elif exp and exp > today + dt.timedelta(days=MAX_EXCEPTION_DAYS):
            problems.append(f"vigencia mayor a {MAX_EXCEPTION_DAYS} días")
        (invalid if problems else valid).append((e, problems))
    return [e for e, _ in valid], invalid


def suppressed_by(finding: Finding, exceptions) -> dict | None:
    for e in exceptions:
        if str(e["tool"]).lower() != finding.tool.lower():
            continue
        if not fnmatch.fnmatchcase(norm_id(finding.rule), norm_id(e["id"]).replace("\\", "")) and \
                not fnmatch.fnmatchcase(finding.rule.upper(), str(e["id"]).upper()):
            continue
        if e.get("path") and not fnmatch.fnmatchcase(finding.path, str(e["path"])):
            continue
        if e.get("package") and not fnmatch.fnmatchcase(finding.package, str(e["package"])):
            continue
        return e
    return None


# --------------------------------------------------------------- evaluation
def fix_matches(mode: str, f: Finding) -> bool:
    return mode == "any" or (mode == "fixed" and f.fixed is True) or (mode == "unfixed" and f.fixed is False)


def evaluate(gate: dict, reports: Path, exceptions, invalid_exceptions) -> dict:
    res = {"id": gate["id"], "control": gate["control"], "tool": gate["tool"], "status": "PASS",
           "lines": [], "blocking": [], "suppressed": 0}

    def escalate(status):
        if RANK[status] > RANK[res["status"]]:
            res["status"] = status

    if gate["kind"] == "exceptions":
        if invalid_exceptions:
            escalate("BLOCK")
            for e, problems in invalid_exceptions:
                res["lines"].append(f"excepción {e.get('tool', '?')}/{e.get('id', '?')}: {'; '.join(problems)}")
        else:
            res["lines"].append("todas las excepciones son válidas (o no hay excepciones)")
        return res

    try:
        data = load_json(reports / gate["report"])
        if gate["kind"] == "sbom":
            n = len((data or {}).get("components") or [])
            res["lines"].append(f"{n} componentes en el SBOM (mínimo {gate.get('min_components', 1)})")
            if n < gate.get("min_components", 1):
                escalate("BLOCK")
            return res
        findings = PARSERS[gate["kind"]](data, gate["tool"])
    except ReportError as exc:
        escalate("BLOCK")
        res["lines"].append(f"SIN EVIDENCIA: {exc}")
        return res

    active = []
    for f in findings:
        if suppressed_by(f, exceptions):
            res["suppressed"] += 1
        else:
            active.append(f)

    for rule in gate["rules"]:
        sevs = set(rule["severities"])
        mode = rule.get("fix", "any")
        hits = [f for f in active if f.severity in sevs and fix_matches(mode, f)]
        limit = rule.get("max", 0)
        over = len(hits) > limit
        label = "/".join(rule["severities"]) + (f" ({mode})" if mode != "any" else "")
        res["lines"].append(f"{label}: {len(hits)} (máximo {limit}) -> {rule['action'].upper() if over else 'ok'}")
        if over:
            escalate("BLOCK" if rule["action"] == "block" else "WARN")
            if rule["action"] == "block":
                res["blocking"].extend(hits)
    if res["suppressed"]:
        res["lines"].append(f"{res['suppressed']} hallazgos cubiertos por excepciones vigentes")
    return res


def suggest(results, out_path: Path):
    """Agrupa los hallazgos que bloquean: por (herramienta, regla) o, si hay paquete, por paquete."""
    groups = defaultdict(list)
    for r in results:
        for f in r["blocking"]:
            groups[(f.tool, "*" if f.package else f.rule, f.package)].append(f)
    stubs = []
    for (tool, rule, package), items in sorted(groups.items()):
        stub = {"tool": tool, "id": rule}
        if package:
            stub["package"] = package
        elif len({f.path for f in items}) == 1 and items[0].path:
            stub["path"] = items[0].path   # excepción acotada al archivo
        stub.update({"justification": "TODO: por qué se acepta y qué controles compensan",
                     "owner": "TODO", "expires": "TODO: AAAA-MM-DD",
                     "hallazgos": len(items), "severidad_máxima": max((f.severity for f in items), key=SEVS.index),
                     "ejemplos": sorted({f.rule for f in items})[:3], "ubicación": items[0].location})
        stubs.append(stub)
    out_path.write_text(
        "# Sugerencias automáticas. NO copiar sin triaje: cada grupo se corrige o se acepta con justificación real.\n"
        "# Completar justification, owner y expires (los campos hallazgos/ejemplos/ubicación son informativos y se pueden borrar).\n"
        + yaml.safe_dump({"exceptions": stubs}, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return len(stubs)


def render(results, today) -> str:
    overall = max((r["status"] for r in results), key=lambda s: RANK[s])
    lines = [f"# Resultado del Quality Gate - {today}", "",
             f"**Decisión global: {ICON[overall]}**" + ("  (la liberación se detiene)" if overall == "BLOCK" else ""), "",
             "| Gate | Control | Herramienta | Resultado | Detalle |", "|---|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r['id']} | {r['control']} | {r['tool']} | {ICON[r['status']]} | {'<br>'.join(r['lines'])} |")
    for r in results:
        if r["blocking"]:
            lines += ["", f"### {r['id']} - principales hallazgos que bloquean", ""]
            for f in r["blocking"][:10]:
                lines.append(f"- `{f.rule}` [{f.severity}] {f.location} - {f.title}")
            if len(r["blocking"]) > 10:
                lines.append(f"- ... y {len(r['blocking']) - 10} mas (ver el reporte JSON completo)")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--policy", default="security/quality-gates.yml")
    ap.add_argument("--exceptions", default="security/exceptions.yml")
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--out", default="reports")
    ap.add_argument("--suggest", action="store_true", help="genera exceptions-suggested.yml")
    ap.add_argument("--today", help="AAAA-MM-DD (solo para pruebas)")
    args = ap.parse_args(argv)

    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
    policy = yaml.safe_load(Path(args.policy).read_text(encoding="utf-8"))
    exceptions, invalid = load_exceptions(Path(args.exceptions), today)
    reports, out = Path(args.reports), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    results = [evaluate(g, reports, exceptions, invalid) for g in policy["gates"]]
    summary = render(results, today)
    (out / "gate-summary.md").write_text(summary, encoding="utf-8")
    (out / "gate-result.json").write_text(json.dumps(
        [{k: v for k, v in r.items() if k != "blocking"} | {"blocking_count": len(r["blocking"])} for r in results],
        indent=2, ensure_ascii=False), encoding="utf-8")
    if args.suggest:
        n = suggest(results, out / "exceptions-suggested.yml")
        print(f"[suggest] {n} grupos de hallazgos -> {out / 'exceptions-suggested.yml'}")
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(summary)
    return 1 if any(r["status"] == "BLOCK" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
