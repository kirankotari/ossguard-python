"""Tests for analyzers (dep_health, drift, watch, tpn, reach) — unit tests with mocked APIs."""

import json
from unittest.mock import MagicMock, patch


from ossguard.apis.osv import VulnInfo
from ossguard.apis.deps_dev import PackageInfo
from ossguard.parsers.dependencies import Dependency


class TestDepHealth:
    @patch("ossguard.analyzers.dep_health.DepsDevClient")
    @patch("ossguard.analyzers.dep_health.OSVClient")
    def test_analyze_no_vulns(self, mock_osv_cls, mock_ddc_cls):
        from ossguard.analyzers.dep_health import analyze_dependencies

        # Mock OSV returns no vulns
        mock_osv = MagicMock()
        mock_osv.query_batch.return_value = {}
        mock_osv_cls.return_value.__enter__ = MagicMock(return_value=mock_osv)
        mock_osv_cls.return_value.__exit__ = MagicMock(return_value=False)

        # Mock deps.dev returns basic info
        mock_ddc = MagicMock()
        mock_ddc.get_version.return_value = PackageInfo(
            name="requests", latest_version="2.31.0", license="Apache-2.0"
        )
        mock_ddc.get_package.return_value = PackageInfo(
            name="requests", latest_version="2.31.0", license="Apache-2.0"
        )
        mock_ddc_cls.return_value.__enter__ = MagicMock(return_value=mock_ddc)
        mock_ddc_cls.return_value.__exit__ = MagicMock(return_value=False)

        deps = [Dependency(name="requests", version="2.31.0", ecosystem="pypi")]
        report = analyze_dependencies(deps)

        assert report.total_deps == 1
        assert report.total_vulns == 0
        assert report.aggregate_score >= 9.0
        assert report.risk_summary == "HEALTHY"

    @patch("ossguard.analyzers.dep_health.DepsDevClient")
    @patch("ossguard.analyzers.dep_health.OSVClient")
    def test_analyze_with_vulns(self, mock_osv_cls, mock_ddc_cls):
        from ossguard.analyzers.dep_health import analyze_dependencies

        vuln = VulnInfo(id="GHSA-1234", severity="HIGH", summary="XSS vulnerability")

        mock_osv = MagicMock()
        mock_osv.query_batch.return_value = {"lodash": [vuln]}
        mock_osv_cls.return_value.__enter__ = MagicMock(return_value=mock_osv)
        mock_osv_cls.return_value.__exit__ = MagicMock(return_value=False)

        mock_ddc = MagicMock()
        mock_ddc.get_version.return_value = PackageInfo(name="lodash", latest_version="4.17.21")
        mock_ddc_cls.return_value.__enter__ = MagicMock(return_value=mock_ddc)
        mock_ddc_cls.return_value.__exit__ = MagicMock(return_value=False)

        deps = [Dependency(name="lodash", version="4.17.20", ecosystem="npm")]
        report = analyze_dependencies(deps)

        assert report.total_vulns == 1
        assert report.high_vulns == 1
        assert report.risk_summary == "HIGH"

    @patch("ossguard.analyzers.dep_health.DepsDevClient")
    @patch("ossguard.analyzers.dep_health.OSVClient")
    def test_excludes_dev_deps_by_default(self, mock_osv_cls, mock_ddc_cls):
        from ossguard.analyzers.dep_health import analyze_dependencies

        mock_osv = MagicMock()
        mock_osv.query_batch.return_value = {}
        mock_osv_cls.return_value.__enter__ = MagicMock(return_value=mock_osv)
        mock_osv_cls.return_value.__exit__ = MagicMock(return_value=False)

        mock_ddc = MagicMock()
        mock_ddc.get_version.return_value = None
        mock_ddc.get_package.return_value = None
        mock_ddc_cls.return_value.__enter__ = MagicMock(return_value=mock_ddc)
        mock_ddc_cls.return_value.__exit__ = MagicMock(return_value=False)

        deps = [
            Dependency(name="requests", version="2.31.0", ecosystem="pypi", is_dev=False),
            Dependency(name="pytest", version="7.0.0", ecosystem="pypi", is_dev=True),
        ]
        report = analyze_dependencies(deps, include_dev=False)
        assert report.total_deps == 1

    def test_dep_health_result_properties(self):
        from ossguard.analyzers.dep_health import DepHealthResult

        vulns = [
            VulnInfo(id="CVE-1", severity="CRITICAL"),
            VulnInfo(id="CVE-2", severity="HIGH"),
            VulnInfo(id="CVE-3", severity="MEDIUM"),
        ]
        dep = Dependency(name="test", version="1.0", ecosystem="npm")
        result = DepHealthResult(dep=dep, vulns=vulns, health_score=3.0)

        assert result.vuln_count == 3
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.risk_level == "CRITICAL"


class TestDrift:
    def test_drift_added_removed(self, tmp_path):
        from ossguard.analyzers.drift import analyze_drift

        old_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"name": "app", "version": "1.0"}},
            "components": [
                {
                    "type": "library",
                    "name": "lodash",
                    "version": "4.17.20",
                    "purl": "pkg:npm/lodash@4.17.20",
                },
                {
                    "type": "library",
                    "name": "react",
                    "version": "18.0.0",
                    "purl": "pkg:npm/react@18.0.0",
                },
            ],
        }
        new_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"name": "app", "version": "1.1"}},
            "components": [
                {
                    "type": "library",
                    "name": "lodash",
                    "version": "4.17.21",
                    "purl": "pkg:npm/lodash@4.17.21",
                },
                {
                    "type": "library",
                    "name": "express",
                    "version": "4.18.0",
                    "purl": "pkg:npm/express@4.18.0",
                },
            ],
        }

        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"
        old_path.write_text(json.dumps(old_sbom))
        new_path.write_text(json.dumps(new_sbom))

        report = analyze_drift(str(old_path), str(new_path), check_vulns=False)

        assert report.added == 1  # express
        assert report.removed == 1  # react
        assert report.upgraded == 1  # lodash 4.17.20 -> 4.17.21
        assert report.total_changes == 3

    def test_drift_no_changes(self, tmp_path):
        from ossguard.analyzers.drift import analyze_drift

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"name": "app", "version": "1.0"}},
            "components": [
                {
                    "type": "library",
                    "name": "lodash",
                    "version": "4.17.21",
                    "purl": "pkg:npm/lodash@4.17.21",
                },
            ],
        }

        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"
        old_path.write_text(json.dumps(sbom))
        new_path.write_text(json.dumps(sbom))

        report = analyze_drift(str(old_path), str(new_path), check_vulns=False)
        assert report.total_changes == 0
        assert report.risk_delta == "UNCHANGED"


class TestWatch:
    @patch("ossguard.analyzers.watch.OSVClient")
    def test_watch_clean_sbom(self, mock_osv_cls, tmp_path):
        from ossguard.analyzers.watch import watch_sbom

        mock_osv = MagicMock()
        mock_osv.query_batch.return_value = {}
        mock_osv_cls.return_value.__enter__ = MagicMock(return_value=mock_osv)
        mock_osv_cls.return_value.__exit__ = MagicMock(return_value=False)

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"name": "app", "version": "1.0"}},
            "components": [
                {
                    "type": "library",
                    "name": "lodash",
                    "version": "4.17.21",
                    "purl": "pkg:npm/lodash@4.17.21",
                },
            ],
        }
        sbom_path = tmp_path / "sbom.json"
        sbom_path.write_text(json.dumps(sbom))

        report = watch_sbom(str(sbom_path))
        assert report.is_clean
        assert report.total_components == 1
        assert report.total_vulns == 0

    @patch("ossguard.analyzers.watch.OSVClient")
    def test_watch_with_vulns(self, mock_osv_cls, tmp_path):
        from ossguard.analyzers.watch import watch_sbom

        vuln = VulnInfo(id="CVE-2024-1234", severity="HIGH", summary="Bad stuff")

        mock_osv = MagicMock()
        mock_osv.query_batch.return_value = {"lodash": [vuln]}
        mock_osv_cls.return_value.__enter__ = MagicMock(return_value=mock_osv)
        mock_osv_cls.return_value.__exit__ = MagicMock(return_value=False)

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"name": "app", "version": "1.0"}},
            "components": [
                {
                    "type": "library",
                    "name": "lodash",
                    "version": "4.17.20",
                    "purl": "pkg:npm/lodash@4.17.20",
                },
            ],
        }
        sbom_path = tmp_path / "sbom.json"
        sbom_path.write_text(json.dumps(sbom))

        report = watch_sbom(str(sbom_path))
        assert not report.is_clean
        assert report.affected_components == 1
        assert report.total_vulns == 1

    @patch("ossguard.analyzers.watch.OSVClient")
    def test_watch_to_json(self, mock_osv_cls, tmp_path):
        from ossguard.analyzers.watch import watch_sbom

        mock_osv = MagicMock()
        mock_osv.query_batch.return_value = {}
        mock_osv_cls.return_value.__enter__ = MagicMock(return_value=mock_osv)
        mock_osv_cls.return_value.__exit__ = MagicMock(return_value=False)

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"name": "app", "version": "1.0"}},
            "components": [],
        }
        sbom_path = tmp_path / "sbom.json"
        sbom_path.write_text(json.dumps(sbom))

        report = watch_sbom(str(sbom_path))
        json_str = report.to_json()
        data = json.loads(json_str)
        assert "sbom_name" in data
        assert "alerts" in data


class TestTPN:
    @patch("ossguard.analyzers.tpn.DepsDevClient")
    def test_generate_tpn(self, mock_ddc_cls):
        from ossguard.analyzers.tpn import generate_tpn

        mock_ddc = MagicMock()
        mock_ddc.get_version.return_value = PackageInfo(
            name="requests", license="Apache-2.0", homepage="https://requests.readthedocs.io"
        )
        mock_ddc.get_package.return_value = None
        mock_ddc_cls.return_value.__enter__ = MagicMock(return_value=mock_ddc)
        mock_ddc_cls.return_value.__exit__ = MagicMock(return_value=False)

        deps = [Dependency(name="requests", version="2.31.0", ecosystem="pypi")]
        report = generate_tpn(deps, project_name="myapp")

        assert len(report.entries) == 1
        assert report.entries[0].license == "Apache-2.0"
        assert report.project_name == "myapp"

    @patch("ossguard.analyzers.tpn.DepsDevClient")
    def test_tpn_unknown_license(self, mock_ddc_cls):
        from ossguard.analyzers.tpn import generate_tpn

        mock_ddc = MagicMock()
        mock_ddc.get_version.return_value = PackageInfo(name="mystery", license="")
        mock_ddc.get_package.return_value = None
        mock_ddc_cls.return_value.__enter__ = MagicMock(return_value=mock_ddc)
        mock_ddc_cls.return_value.__exit__ = MagicMock(return_value=False)

        deps = [Dependency(name="mystery", version="1.0", ecosystem="npm")]
        report = generate_tpn(deps)

        assert "mystery" in report.unknown_licenses

    @patch("ossguard.analyzers.tpn.DepsDevClient")
    def test_tpn_output_formats(self, mock_ddc_cls):
        from ossguard.analyzers.tpn import generate_tpn

        mock_ddc = MagicMock()
        mock_ddc.get_version.return_value = PackageInfo(name="react", license="MIT")
        mock_ddc.get_package.return_value = None
        mock_ddc_cls.return_value.__enter__ = MagicMock(return_value=mock_ddc)
        mock_ddc_cls.return_value.__exit__ = MagicMock(return_value=False)

        deps = [Dependency(name="react", version="18.2.0", ecosystem="npm")]
        report = generate_tpn(deps, project_name="test")

        text = report.to_text()
        assert "react" in text
        assert "MIT" in text

        html = report.to_html()
        assert "<table>" in html
        assert "react" in html

        json_str = report.to_json()
        data = json.loads(json_str)
        assert data["total_components"] == 1

    @patch("ossguard.analyzers.tpn.DepsDevClient")
    def test_tpn_skips_dev_deps(self, mock_ddc_cls):
        from ossguard.analyzers.tpn import generate_tpn

        mock_ddc = MagicMock()
        mock_ddc.get_version.return_value = PackageInfo(name="react", license="MIT")
        mock_ddc.get_package.return_value = None
        mock_ddc_cls.return_value.__enter__ = MagicMock(return_value=mock_ddc)
        mock_ddc_cls.return_value.__exit__ = MagicMock(return_value=False)

        deps = [
            Dependency(name="react", version="18.2.0", ecosystem="npm", is_dev=False),
            Dependency(name="jest", version="29.0.0", ecosystem="npm", is_dev=True),
        ]
        report = generate_tpn(deps)
        assert len(report.entries) == 1
        assert report.entries[0].name == "react"


class TestReach:
    @patch("ossguard.analyzers.reach.OSVClient")
    def test_reachability_analysis(self, mock_osv_cls, tmp_path):
        from ossguard.analyzers.reach import analyze_reachability

        mock_osv = MagicMock()
        mock_osv.query_batch.return_value = {
            "requests": [VulnInfo(id="CVE-1", severity="HIGH")],
            "unused-lib": [VulnInfo(id="CVE-2", severity="CRITICAL")],
        }
        mock_osv_cls.return_value.__enter__ = MagicMock(return_value=mock_osv)
        mock_osv_cls.return_value.__exit__ = MagicMock(return_value=False)

        # Create a Python source file that imports requests
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "app.py").write_text("import requests\nfrom pathlib import Path\n")

        deps = [
            Dependency(name="requests", version="2.31.0", ecosystem="pypi"),
            Dependency(name="unused-lib", version="1.0.0", ecosystem="pypi"),
        ]

        report = analyze_reachability(deps, tmp_path)

        assert report.total_deps == 2
        assert report.reachable_deps == 1
        assert report.reachable_vulns == 1
        assert report.filtered_vulns == 1
        assert report.noise_reduction_pct == 50.0

    @patch("ossguard.analyzers.reach.OSVClient")
    def test_reachability_no_vulns(self, mock_osv_cls, tmp_path):
        from ossguard.analyzers.reach import analyze_reachability

        mock_osv = MagicMock()
        mock_osv.query_batch.return_value = {}
        mock_osv_cls.return_value.__enter__ = MagicMock(return_value=mock_osv)
        mock_osv_cls.return_value.__exit__ = MagicMock(return_value=False)

        deps = [Dependency(name="requests", version="2.31.0", ecosystem="pypi")]
        report = analyze_reachability(deps, tmp_path)

        assert report.total_vulns == 0
        assert report.noise_reduction_pct == 0.0

    @patch("ossguard.analyzers.reach.OSVClient")
    def test_reachability_js_imports(self, mock_osv_cls, tmp_path):
        from ossguard.analyzers.reach import analyze_reachability

        mock_osv = MagicMock()
        mock_osv.query_batch.return_value = {}
        mock_osv_cls.return_value.__enter__ = MagicMock(return_value=mock_osv)
        mock_osv_cls.return_value.__exit__ = MagicMock(return_value=False)

        (tmp_path / "index.js").write_text(
            "const express = require('express');\nimport React from 'react';\n"
        )

        deps = [
            Dependency(name="express", version="4.18.0", ecosystem="npm"),
            Dependency(name="react", version="18.2.0", ecosystem="npm"),
            Dependency(name="lodash", version="4.17.21", ecosystem="npm"),
        ]

        report = analyze_reachability(deps, tmp_path)
        assert report.reachable_deps == 2  # express and react
