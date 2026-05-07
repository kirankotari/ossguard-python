# Contributing to OSSGuard

Thank you for your interest in contributing to OSSGuard! This project follows the [OpenSSF Community Guidelines](https://openssf.org/community/).

## Getting Started

1. **Fork** the repository and clone your fork:
   ```bash
   git clone https://github.com/<your-username>/ossguard.git
   cd ossguard
   ```

2. **Install** in development mode:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

3. **Run tests** to verify your setup:
   ```bash
   pytest
   ```

## Development Workflow

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```

2. Make your changes, ensuring:
   - Code follows existing style (enforced by `ruff`)
   - All existing tests continue to pass
   - New features include tests
   - Public functions include docstrings

3. Run the linter and tests:
   ```bash
   ruff check src/ tests/
   pytest
   ```

4. Commit with a descriptive message:
   ```bash
   git commit -m "feat: add my-feature description"
   ```

5. Push and open a Pull Request against `main`.

## Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` — new feature
- `fix:` — bug fix
- `docs:` — documentation only
- `test:` — adding or updating tests
- `refactor:` — code change that neither fixes a bug nor adds a feature
- `ci:` — CI/CD changes
- `chore:` — maintenance tasks

## Adding a New Analyzer / Command

1. Create `src/ossguard/analyzers/<name>.py` with:
   - A dataclass for the report (e.g., `MyReport`)
   - A public function (e.g., `check_my_thing(project_path)`)
2. Add the CLI command in `src/ossguard/cli.py`
3. Add tests in `tests/test_analyzers_*.py`
4. Update `README.md` with the new command

## Reporting Issues

- Use [GitHub Issues](https://github.com/kirankotari/ossguard/issues)
- Include steps to reproduce, expected behavior, and actual behavior
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
