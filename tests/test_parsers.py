"""Tests for dependency and SBOM parsers."""

import json

import pytest

from ossguard.parsers.dependencies import Dependency, parse_dependencies
from ossguard.parsers.sbom import parse_sbom


class TestDependencyParser:
    def test_empty_directory(self, tmp_path):
        deps = parse_dependencies(tmp_path)
        assert deps == []

    def test_parse_package_json(self, tmp_path):
        pkg = {
            "name": "test-app",
            "dependencies": {"react": "^18.2.0", "express": "~4.18.0"},
            "devDependencies": {"jest": "^29.0.0"},
        }
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        deps = parse_dependencies(tmp_path)

        names = [d.name for d in deps]
        assert "react" in names
        assert "express" in names
        assert "jest" in names

        react = next(d for d in deps if d.name == "react")
        assert react.ecosystem == "npm"
        assert react.version == "18.2.0"
        assert not react.is_dev

        jest = next(d for d in deps if d.name == "jest")
        assert jest.is_dev

    def test_parse_requirements_txt(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "requests==2.31.0\nflask>=2.0.0\n# comment\n-r other.txt\nrich\n"
        )
        deps = parse_dependencies(tmp_path)

        names = [d.name for d in deps]
        assert "requests" in names
        assert "flask" in names
        assert "rich" in names

        requests_dep = next(d for d in deps if d.name == "requests")
        assert requests_dep.version == "2.31.0"
        assert requests_dep.ecosystem == "pypi"

    def test_parse_pyproject_toml(self, tmp_path):
        content = """[project]
name = "myapp"
dependencies = [
    "typer>=0.9.0",
    "rich>=13.0.0",
    "httpx>=0.27.0",
]
"""
        (tmp_path / "pyproject.toml").write_text(content)
        deps = parse_dependencies(tmp_path)

        names = [d.name for d in deps]
        assert "typer" in names
        assert "rich" in names
        assert "httpx" in names

        typer_dep = next(d for d in deps if d.name == "typer")
        assert typer_dep.ecosystem == "pypi"

    def test_parse_go_mod(self, tmp_path):
        content = """module github.com/example/app

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgithub.com/stretchr/testify v1.8.4
)
"""
        (tmp_path / "go.mod").write_text(content)
        deps = parse_dependencies(tmp_path)

        names = [d.name for d in deps]
        assert "github.com/gin-gonic/gin" in names

        gin = next(d for d in deps if d.name == "github.com/gin-gonic/gin")
        assert gin.version == "v1.9.1"
        assert gin.ecosystem == "go"

    def test_parse_cargo_toml(self, tmp_path):
        content = """[package]
name = "myapp"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.32", features = ["full"] }

[dev-dependencies]
criterion = "0.5"
"""
        (tmp_path / "Cargo.toml").write_text(content)
        deps = parse_dependencies(tmp_path)

        names = [d.name for d in deps]
        assert "serde" in names
        assert "tokio" in names
        assert "criterion" in names

        serde = next(d for d in deps if d.name == "serde")
        assert serde.ecosystem == "crates.io"
        assert serde.version == "1.0"

        criterion = next(d for d in deps if d.name == "criterion")
        assert criterion.is_dev

    def test_parse_pom_xml(self, tmp_path):
        content = """<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.0</version>
    </dependency>
  </dependencies>
</project>"""
        (tmp_path / "pom.xml").write_text(content)
        deps = parse_dependencies(tmp_path)

        assert len(deps) >= 1
        spring = next(d for d in deps if "spring-core" in d.name)
        assert spring.ecosystem == "maven"
        assert spring.version == "5.3.0"

    def test_parse_composer_json(self, tmp_path):
        data = {
            "require": {"monolog/monolog": "^2.0", "php": ">=8.0"},
            "require-dev": {"phpunit/phpunit": "^9.0"},
        }
        (tmp_path / "composer.json").write_text(json.dumps(data))
        deps = parse_dependencies(tmp_path)

        names = [d.name for d in deps]
        assert "monolog/monolog" in names
        # php itself should be excluded
        assert "php" not in names

    def test_deduplication(self, tmp_path):
        # Both pyproject.toml and requirements.txt mention the same package
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["requests>=2.28.0"]')
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        deps = parse_dependencies(tmp_path)

        request_deps = [d for d in deps if d.name == "requests"]
        assert len(request_deps) == 1

    def test_display_name(self):
        dep = Dependency(name="react", version="18.2.0", ecosystem="npm")
        assert dep.display_name == "react@18.2.0"

        dep2 = Dependency(name="react", ecosystem="npm")
        assert dep2.display_name == "react"

    def test_nonexistent_path(self):
        deps = parse_dependencies("/nonexistent/path")
        assert deps == []


class TestSBOMParser:
    def test_parse_cyclonedx(self, tmp_path):
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"name": "myapp", "version": "1.0.0"}},
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
                    "version": "4.18.2",
                    "purl": "pkg:npm/express@4.18.2",
                },
            ],
        }
        sbom_path = tmp_path / "sbom.json"
        sbom_path.write_text(json.dumps(sbom))

        result = parse_sbom(sbom_path)
        assert result.format == "cyclonedx"
        assert result.name == "myapp"
        assert len(result.dependencies) == 2

        lodash = next(d for d in result.dependencies if d.name == "lodash")
        assert lodash.version == "4.17.21"
        assert lodash.ecosystem == "npm"

    def test_parse_spdx(self, tmp_path):
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "name": "myapp",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-requests",
                    "name": "requests",
                    "versionInfo": "2.31.0",
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.31.0"}
                    ],
                },
            ],
        }
        sbom_path = tmp_path / "sbom.json"
        sbom_path.write_text(json.dumps(sbom))

        result = parse_sbom(sbom_path)
        assert result.format == "spdx"
        assert result.name == "myapp"
        assert len(result.dependencies) == 1

        req = result.dependencies[0]
        assert req.name == "requests"
        assert req.ecosystem == "pypi"

    def test_unknown_format_raises(self, tmp_path):
        sbom_path = tmp_path / "bad.json"
        sbom_path.write_text(json.dumps({"random": "data"}))

        with pytest.raises(ValueError, match="Unrecognized SBOM format"):
            parse_sbom(sbom_path)
