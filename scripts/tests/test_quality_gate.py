"""Pruebas del evaluador de quality gates con reportes sintéticos.
Ejecutar:  python -m unittest discover -s scripts/tests -v   (desde la raiz del repo)
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import quality_gate as qg  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "security" / "quality-gates.yml"


def write(d: Path, name: str, data):
    (d / name).write_text(json.dumps(data), encoding="utf-8")


def clean_reports(d: Path):
    write(d, "gitleaks.json", [])
    write(d, "semgrep.json", {"results": []})
    for n in ("trivy-sca.json", "trivy-image.json", "trivy-iac.json"):
        write(d, n, {"Results": []})
    write(d, "sbom.cdx.json", {"components": [{"name": "express"}]})
    write(d, "zap.json", {"site": [{"alerts": []}]})


def run(reports: Path, exceptions: Path | None = None, today="2026-10-13"):
    exc = exceptions or (reports / "none.yml")
    return qg.main(["--policy", str(POLICY), "--exceptions", str(exc), "--reports", str(reports),
                    "--out", str(reports / "out"), "--suggest", "--today", today])


class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        clean_reports(self.d)

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_passes(self):
        self.assertEqual(run(self.d), 0)

    def test_secret_blocks(self):
        write(self.d, "gitleaks.json", [{"RuleID": "private-key", "File": "lib/insecurity.ts", "StartLine": 21}])
        self.assertEqual(run(self.d), 1)

    def test_semgrep_error_blocks_warning_only_warns(self):
        write(self.d, "semgrep.json", {"results": [{"check_id": "r1", "path": "a.ts", "start": {"line": 1},
                                                    "extra": {"severity": "WARNING", "message": "m"}}]})
        self.assertEqual(run(self.d), 0)
        write(self.d, "semgrep.json", {"results": [{"check_id": "r1", "path": "a.ts", "start": {"line": 1},
                                                    "extra": {"severity": "ERROR", "message": "m"}}]})
        self.assertEqual(run(self.d), 1)

    def test_sca_high_without_fix_only_warns(self):
        v = {"VulnerabilityID": "CVE-1", "PkgName": "x", "InstalledVersion": "1", "Severity": "HIGH"}
        write(self.d, "trivy-sca.json", {"Results": [{"Target": "package-lock.json", "Vulnerabilities": [v]}]})
        self.assertEqual(run(self.d), 0)
        v["FixedVersion"] = "2"
        write(self.d, "trivy-sca.json", {"Results": [{"Target": "package-lock.json", "Vulnerabilities": [v]}]})
        self.assertEqual(run(self.d), 1)

    def test_missing_report_blocks(self):
        (self.d / "zap.json").unlink()
        self.assertEqual(run(self.d), 1)

    def test_empty_sbom_blocks(self):
        write(self.d, "sbom.cdx.json", {"components": []})
        self.assertEqual(run(self.d), 1)

    def test_misconfig_id_normalization_and_valid_exception(self):
        m = {"ID": "KSV-0014", "Severity": "HIGH", "Status": "FAIL", "Title": "readOnlyRootFilesystem"}
        write(self.d, "trivy-iac.json", {"Results": [{"Target": "k8s/deployment.yaml", "Misconfigurations": [m]}]})
        self.assertEqual(run(self.d), 1)
        exc = self.d / "exc.yml"
        exc.write_text("exceptions:\n- {tool: trivy-iac, id: KSV014, path: 'k8s/*', justification: 'prueba',"
                       " owner: 'Ana', expires: '2026-12-01'}\n")
        self.assertEqual(run(self.d, exc), 0)

    def test_expired_or_todo_exception_blocks_and_does_not_suppress(self):
        write(self.d, "gitleaks.json", [{"RuleID": "k", "File": "f", "StartLine": 1}])
        exc = self.d / "exc.yml"
        exc.write_text("exceptions:\n- {tool: gitleaks, id: k, justification: 'ok', owner: 'Ana', expires: '2026-01-01'}\n")
        self.assertEqual(run(self.d, exc), 1)
        exc.write_text("exceptions:\n- {tool: gitleaks, id: k, justification: 'TODO', owner: 'Ana', expires: '2026-12-01'}\n")
        self.assertEqual(run(self.d, exc), 1)

    def test_exception_too_long_and_wildcard_rejected(self):
        exc = self.d / "exc.yml"
        exc.write_text("exceptions:\n- {tool: gitleaks, id: k, justification: 'ok', owner: 'Ana', expires: '2027-12-01'}\n"
                       "- {tool: gitleaks, id: '*', justification: 'ok', owner: 'Ana', expires: '2026-12-01'}\n")
        self.assertEqual(run(self.d, exc), 1)

    def test_package_exception_for_cves(self):
        v1 = {"VulnerabilityID": "CVE-2021-1", "PkgName": "lodash", "InstalledVersion": "2", "Severity": "CRITICAL"}
        write(self.d, "trivy-image.json", {"Results": [{"Target": "node-pkg", "Vulnerabilities": [v1]}]})
        exc = self.d / "exc.yml"
        exc.write_text("exceptions:\n- {tool: trivy-image, id: 'CVE-*', package: lodash, justification: 'reto',"
                       " owner: 'Ana', expires: '2026-12-01'}\n")
        self.assertEqual(run(self.d, exc), 0)

    def test_wildcard_id_allowed_only_with_package(self):
        v = {"VulnerabilityID": "GHSA-xxxx", "PkgName": "lodash", "InstalledVersion": "2", "Severity": "CRITICAL"}
        write(self.d, "trivy-sca.json", {"Results": [{"Target": "package-lock.json", "Vulnerabilities": [v]}]})
        exc = self.d / "exc.yml"
        exc.write_text("exceptions:\n- {tool: trivy-sca, id: '*', package: lodash, justification: 'reto',"
                       " owner: 'Ana', expires: '2026-12-01'}\n")
        self.assertEqual(run(self.d, exc), 0)

    def test_image_secret_blocks_and_path_exception_suppresses(self):
        # Caso real de la ejecución 1: clave privada HIGH dentro de la imagen que antes no se contaba.
        s = {"RuleID": "private-key", "Severity": "HIGH", "Title": "Asymmetric Private Key", "StartLine": 21}
        write(self.d, "trivy-image.json", {"Results": [{"Target": "/juice-shop/lib/insecurity.ts", "Secrets": [s]}]})
        self.assertEqual(run(self.d), 1)
        exc = self.d / "exc.yml"
        exc.write_text("exceptions:\n- {tool: trivy-image, id: private-key, path: '/juice-shop/*lib/insecurity.*',"
                       " justification: 'reto', owner: 'Ana', expires: '2026-12-01'}\n")
        self.assertEqual(run(self.d, exc), 0)

    def test_suggestions_file_is_generated(self):
        write(self.d, "gitleaks.json", [{"RuleID": "k", "File": "f", "StartLine": 1}])
        run(self.d)
        self.assertIn("TODO", (self.d / "out" / "exceptions-suggested.yml").read_text())


if __name__ == "__main__":
    unittest.main()
