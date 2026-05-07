"""Fuzzing readiness check — detect existing fuzz setup and generate starter harnesses."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ossguard.detector import ProjectInfo, detect_project


@dataclass
class FuzzFinding:
    """A fuzzing-related finding or recommendation."""

    category: str  # "existing", "recommendation", "starter"
    description: str
    file: str = ""
    details: str = ""


@dataclass
class FuzzReport:
    """Fuzzing readiness assessment report."""

    has_fuzzing: bool = False
    framework: str = ""
    findings: list[FuzzFinding] = field(default_factory=list)
    readiness_score: int = 0  # 0-100
    starter_harness: str = ""  # Generated starter code
    language: str = ""


def check_fuzz_readiness(project_path: str | Path) -> FuzzReport:
    """Check if a project has fuzzing set up and generate recommendations.

    Args:
        project_path: Path to the project.

    Returns:
        FuzzReport with readiness assessment and starter harness.
    """
    path = Path(project_path).resolve()
    info = detect_project(path)

    findings: list[FuzzFinding] = []
    has_fuzzing = False
    framework = ""
    score = 0
    lang = info.primary_language or ""

    # Check for existing fuzz setups
    has_fuzzing, framework, fuzz_findings = _detect_existing_fuzz(path, info)
    findings.extend(fuzz_findings)

    if has_fuzzing:
        score += 50

    # Check for OSS-Fuzz integration
    oss_fuzz_findings = _check_oss_fuzz(path)
    findings.extend(oss_fuzz_findings)
    if any(f.category == "existing" and "OSS-Fuzz" in f.description for f in oss_fuzz_findings):
        score += 20

    # Check for ClusterFuzzLite
    cfl_findings = _check_clusterfuzzlite(path)
    findings.extend(cfl_findings)
    if any(f.category == "existing" for f in cfl_findings):
        score += 15

    # Check CI integration
    ci_findings = _check_fuzz_ci(path)
    findings.extend(ci_findings)
    if any(f.category == "existing" for f in ci_findings):
        score += 15

    # Generate recommendations if no fuzzing found
    if not has_fuzzing:
        findings.extend(_generate_recommendations(lang, info))

    # Generate starter harness
    starter = _generate_starter_harness(lang, path)

    return FuzzReport(
        has_fuzzing=has_fuzzing,
        framework=framework,
        findings=findings,
        readiness_score=min(score, 100),
        starter_harness=starter,
        language=lang,
    )


def _detect_existing_fuzz(path: Path, info: ProjectInfo) -> tuple[bool, str, list[FuzzFinding]]:
    """Detect existing fuzz testing frameworks."""
    findings: list[FuzzFinding] = []
    has_fuzz = False
    framework = ""

    lang = (info.primary_language or "").lower()

    # Python: atheris, hypothesis
    if lang == "python":
        for py_file in path.rglob("*.py"):
            if any(skip in str(py_file) for skip in ["venv", ".venv", "node_modules", ".git"]):
                continue
            try:
                content = py_file.read_text(errors="ignore")[:2000]
                if "atheris" in content:
                    has_fuzz = True
                    framework = "Atheris"
                    findings.append(FuzzFinding("existing", f"Atheris fuzzer found in {py_file.name}", str(py_file)))
                if "hypothesis" in content and "@given" in content:
                    has_fuzz = True
                    framework = framework or "Hypothesis"
                    findings.append(FuzzFinding("existing", f"Hypothesis property tests in {py_file.name}", str(py_file)))
            except Exception:
                continue

    # Go: go test -fuzz
    elif lang == "go":
        for go_file in path.rglob("*_test.go"):
            try:
                content = go_file.read_text(errors="ignore")
                if "func Fuzz" in content:
                    has_fuzz = True
                    framework = "Go native fuzzing"
                    findings.append(FuzzFinding("existing", f"Go fuzz function found in {go_file.name}", str(go_file)))
            except Exception:
                continue

    # Rust: cargo-fuzz
    elif lang == "rust":
        fuzz_dir = path / "fuzz"
        if fuzz_dir.is_dir():
            has_fuzz = True
            framework = "cargo-fuzz"
            findings.append(FuzzFinding("existing", "cargo-fuzz directory found", "fuzz/"))
        cargo_fuzz = path / "fuzz" / "Cargo.toml"
        if cargo_fuzz.exists():
            has_fuzz = True
            framework = "cargo-fuzz"

    # C/C++: libFuzzer, AFL
    elif lang in ("c", "c++"):
        for src in path.rglob("*"):
            if src.suffix in (".c", ".cpp", ".cc", ".h"):
                try:
                    content = src.read_text(errors="ignore")[:2000]
                    if "LLVMFuzzerTestOneInput" in content:
                        has_fuzz = True
                        framework = "libFuzzer"
                        findings.append(FuzzFinding("existing", f"libFuzzer harness in {src.name}", str(src)))
                except Exception:
                    continue

    # JavaScript/TypeScript: jsfuzz, fast-check
    elif lang in ("javascript", "typescript"):
        pkg_json = path / "package.json"
        if pkg_json.exists():
            import json
            try:
                data = json.loads(pkg_json.read_text())
                all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                if "jsfuzz" in all_deps or "@jazzer.js/core" in all_deps:
                    has_fuzz = True
                    framework = "jsfuzz/Jazzer.js"
                    findings.append(FuzzFinding("existing", "JS fuzzer dependency found"))
                if "fast-check" in all_deps:
                    has_fuzz = True
                    framework = framework or "fast-check"
                    findings.append(FuzzFinding("existing", "fast-check property testing found"))
            except Exception:
                pass

    # Java/Kotlin: Jazzer
    elif lang in ("java", "kotlin"):
        for java_file in path.rglob("*.java"):
            try:
                content = java_file.read_text(errors="ignore")[:2000]
                if "com.code_intelligence.jazzer" in content or "@FuzzTest" in content:
                    has_fuzz = True
                    framework = "Jazzer"
                    findings.append(FuzzFinding("existing", f"Jazzer fuzz test in {java_file.name}", str(java_file)))
            except Exception:
                continue

    return has_fuzz, framework, findings


def _check_oss_fuzz(path: Path) -> list[FuzzFinding]:
    """Check for OSS-Fuzz integration files."""
    findings = []
    oss_fuzz_dir = path / ".oss-fuzz"
    if oss_fuzz_dir.is_dir():
        findings.append(FuzzFinding("existing", "OSS-Fuzz integration found", ".oss-fuzz/"))

    # Check for project.yaml (OSS-Fuzz config)
    for name in ["project.yaml", ".clusterfuzzlite/project.yaml"]:
        if (path / name).exists():
            findings.append(FuzzFinding("existing", f"OSS-Fuzz project config found: {name}", name))

    return findings


def _check_clusterfuzzlite(path: Path) -> list[FuzzFinding]:
    """Check for ClusterFuzzLite setup."""
    findings = []
    cfl_dir = path / ".clusterfuzzlite"
    if cfl_dir.is_dir():
        findings.append(FuzzFinding("existing", "ClusterFuzzLite configuration found", ".clusterfuzzlite/"))

    wf_dir = path / ".github" / "workflows"
    if wf_dir.is_dir():
        for wf in wf_dir.iterdir():
            if wf.suffix in (".yml", ".yaml"):
                try:
                    content = wf.read_text().lower()
                    if "clusterfuzzlite" in content:
                        findings.append(FuzzFinding("existing", f"ClusterFuzzLite workflow: {wf.name}", str(wf)))
                except Exception:
                    pass

    return findings


def _check_fuzz_ci(path: Path) -> list[FuzzFinding]:
    """Check if fuzzing is integrated into CI."""
    findings = []
    wf_dir = path / ".github" / "workflows"
    if wf_dir.is_dir():
        for wf in wf_dir.iterdir():
            if wf.suffix in (".yml", ".yaml"):
                try:
                    content = wf.read_text().lower()
                    if "fuzz" in content and ("run:" in content or "uses:" in content):
                        findings.append(FuzzFinding("existing", f"Fuzz CI workflow: {wf.name}", str(wf)))
                except Exception:
                    pass

    return findings


def _generate_recommendations(lang: str, info: ProjectInfo) -> list[FuzzFinding]:
    """Generate fuzzing recommendations based on language."""
    findings = []
    lang_lower = lang.lower() if lang else ""

    recommendations = {
        "python": [
            ("recommendation", "Install Atheris for Python fuzzing: pip install atheris"),
            ("recommendation", "Consider Hypothesis for property-based testing: pip install hypothesis"),
            ("recommendation", "Apply to OSS-Fuzz for continuous fuzzing coverage"),
        ],
        "go": [
            ("recommendation", "Use native Go fuzzing (Go 1.18+): func FuzzXxx(f *testing.F)"),
            ("recommendation", "Run: go test -fuzz=FuzzXxx ./..."),
            ("recommendation", "Apply to OSS-Fuzz or set up ClusterFuzzLite"),
        ],
        "rust": [
            ("recommendation", "Install cargo-fuzz: cargo install cargo-fuzz"),
            ("recommendation", "Initialize: cargo fuzz init && cargo fuzz add fuzz_target_1"),
            ("recommendation", "Consider AFL.rs as an alternative fuzzer"),
        ],
        "javascript": [
            ("recommendation", "Install Jazzer.js: npm install --save-dev @jazzer.js/core"),
            ("recommendation", "Consider fast-check for property-based testing"),
        ],
        "typescript": [
            ("recommendation", "Install Jazzer.js: npm install --save-dev @jazzer.js/core"),
            ("recommendation", "Consider fast-check for property-based testing"),
        ],
        "java": [
            ("recommendation", "Use Jazzer for Java fuzzing: add com.code_intelligence:jazzer-junit"),
            ("recommendation", "Annotate fuzz test methods with @FuzzTest"),
        ],
        "c": [
            ("recommendation", "Use libFuzzer: implement LLVMFuzzerTestOneInput"),
            ("recommendation", "Compile with: clang -fsanitize=fuzzer,address"),
            ("recommendation", "Apply to OSS-Fuzz for continuous fuzzing"),
        ],
        "c++": [
            ("recommendation", "Use libFuzzer: implement LLVMFuzzerTestOneInput"),
            ("recommendation", "Compile with: clang++ -fsanitize=fuzzer,address"),
            ("recommendation", "Apply to OSS-Fuzz for continuous fuzzing"),
        ],
    }

    for cat, desc in recommendations.get(lang_lower, []):
        findings.append(FuzzFinding(cat, desc))

    # Universal recommendation
    findings.append(FuzzFinding(
        "recommendation",
        "Set up ClusterFuzzLite for CI-integrated fuzzing: https://google.github.io/clusterfuzzlite/",
    ))

    return findings


def _generate_starter_harness(lang: str, path: Path) -> str:
    """Generate a starter fuzz harness for the detected language."""
    lang_lower = (lang or "").lower()

    if lang_lower == "python":
        return '''#!/usr/bin/env python3
"""Fuzz test harness — customize for your project."""
import atheris
import sys

# Import your module here
# from mypackage import parse_input

@atheris.instrument_func
def fuzz_target(data: bytes):
    """Fuzz target — receives random bytes."""
    try:
        # Replace with your function under test
        text = data.decode("utf-8", errors="ignore")
        # parse_input(text)
    except (ValueError, KeyError, IndexError):
        pass  # Expected exceptions

if __name__ == "__main__":
    atheris.Setup(sys.argv, fuzz_target)
    atheris.Fuzz()
'''

    elif lang_lower == "go":
        return '''package mypackage

import "testing"

// FuzzParseInput is a starter fuzz test — customize for your project.
func FuzzParseInput(f *testing.F) {
	// Seed corpus
	f.Add([]byte("hello"))
	f.Add([]byte(""))
	f.Add([]byte("{\"key\": \"value\"}"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Replace with your function under test
		// _, err := ParseInput(string(data))
		// We don't check err — we're looking for panics
	})
}
'''

    elif lang_lower == "rust":
        return '''#![no_main]
use libfuzzer_sys::fuzz_target;

// Import your crate here
// use mycrate::parse;

fuzz_target!(|data: &[u8]| {
    // Replace with your function under test
    if let Ok(s) = std::str::from_utf8(data) {
        // let _ = parse(s);
    }
});
'''

    elif lang_lower in ("c", "c++"):
        return '''#include <stdint.h>
#include <stddef.h>

// Include your headers here
// #include "mylib.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Replace with your function under test
    // parse_input(data, size);
    return 0;
}
'''

    elif lang_lower in ("javascript", "typescript"):
        return '''// Fuzz test using Jazzer.js — customize for your project
// npm install --save-dev @jazzer.js/core

const { fuzz } = require("@jazzer.js/core");

// Import your module here
// const { parseInput } = require("./src/parser");

fuzz((data) => {
  const input = data.toString("utf-8");
  // Replace with your function under test
  // parseInput(input);
});
'''

    elif lang_lower in ("java", "kotlin"):
        return '''import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

// Import your class here
// import com.example.Parser;

class FuzzTests {
    @FuzzTest
    void fuzzParseInput(FuzzedDataProvider data) {
        String input = data.consumeRemainingAsString();
        // Replace with your method under test
        // Parser.parse(input);
    }
}
'''

    return "# No starter harness available for this language.\n# See https://google.github.io/clusterfuzzlite/ for setup guides.\n"
