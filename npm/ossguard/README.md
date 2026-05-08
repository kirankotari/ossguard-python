# ossguard

> One CLI to guard any OSS project with OpenSSF security best practices — bootstrap, scan, and monitor.

## Install

```bash
npm install -g ossguard
```

**No Python required.** npm automatically installs only the pre-built binary for your platform.

## How it works

This package uses platform-specific optional dependencies (like esbuild, Biome, Turbo):

| Package | Platform |
|---------|----------|
| `@ossguard/cli-linux-x64` | Linux x64 |
| `@ossguard/cli-linux-arm64` | Linux arm64 |
| `@ossguard/cli-darwin-x64` | macOS Intel |
| `@ossguard/cli-darwin-arm64` | macOS Apple Silicon |
| `@ossguard/cli-win32-x64` | Windows x64 |

npm only downloads the one matching your OS/arch — no wasted bandwidth.

## Usage

```bash
# Scan a project's security posture
ossguard scan .

# Run a full security audit
ossguard audit .

# Bootstrap OpenSSF best practices
ossguard init .

# See all commands
ossguard --help
```

## Alternative Installation

```bash
# PyPI (requires Python 3.9+)
pip install ossguard

# Homebrew
brew install kirankotari/tap/ossguard
```

## Links

- [GitHub](https://github.com/kirankotari/ossguard)
- [PyPI](https://pypi.org/project/ossguard/)
- [Documentation](https://github.com/kirankotari/ossguard#readme)

## License

Apache-2.0
