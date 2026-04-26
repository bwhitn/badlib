# Contributing

Contributions should keep malware handling conservative and explicit.

## Development

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
mypy src
```

## Guidelines

- Do not add code paths that execute stored samples.
- Prefer explicit file type detection over extension-only checks.
- Keep archive extraction behavior opt-in and documented.
- Add tests for new format detection and storage behavior.
