# Contributing

Clone the repo and set up a local development environment:

```bash
git clone https://github.com/nzhumasseiit/runeguard.git
cd runeguard
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run the test suite:

```bash
pytest
```

Try the CLI and demo:

```bash
runeguard check
runeguard demo
```

Build release artifacts:

```bash
python -m build
```
