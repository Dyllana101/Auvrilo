# Contributing

Thanks for helping improve Auvrilo.

## Local development

1. Follow the setup steps in [README.md](./README.md).
2. Use an isolated virtual environment and a local `.env` file.
3. Run `python -m unittest discover -s tests -v` before opening a pull request.
4. Keep Google credentials, tokens, customer data, and production database files out of commits and test fixtures.

## Pull requests

- Keep changes focused and include tests for behavior changes.
- Update documentation when changing configuration, API behavior, or security assumptions.
- Do not add functionality that bypasses Google's documented Workspace authorization requirements.
- Use mocked Google API responses in automated tests. Do not require real OAuth secrets in CI.
