# Contributing to CoreProbe / opensleuth

Thank you for helping close the gap with commercial forensic tooling.

## Ground rules
- **Honesty over hype.** Never claim a route/capability/tool works unless it
  is real and verified. "Not implemented" and "no public route" are correct
  answers. The repo's reputation is its value.
- **Public research only.** Catalog entries must reference real, publicly
  released exploits/tools. No fabricated CVEs or routes.
- **Lawful use.** Acquisition features are for examiners operating with
  lawful authority. Warrant/authorization gates are non-negotiable.

## Getting started
```bash
git clone https://github.com/xanstomper/coreprobe && cd coreprobe
pip install -e .
cmake -B build -S . && cmake --build build          # native core
python -m pytest tests/ -q                          # 190+ tests
```

## What to work on
- Artifact parsers (new app DBs, more iLEAPP-compatible outputs)
- Exploit catalog entries (verify against source first)
- BFU/escrow/keybag tooling
- Court-ready reporting and chain-of-custody
- Docs, tests, and the web dashboard

## Pull requests
1. Branch from `main`, keep commits focused.
2. Add tests for anything new (mocked where hardware is required).
3. Run the full suite locally before pushing.
4. Update README rows and stance where behavior changes.

## Review expectations
- Routes/tools/disclosures must be traceable to public sources.
- BFU/iCloud claims follow the honesty rules above.
- No secrets in code, logs, or tests.

## License
MIT - see LICENSE. iLEAPP is invoked externally (GPLv3) and is never
vendored into this repository.
