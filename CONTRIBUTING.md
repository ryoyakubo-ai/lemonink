# Contributing

- Open an issue first for new rules or behavior changes.
- Every new rule needs at least one positive fixture and must not fire (at medium or above) on
  `tests/fixtures/benign_*.json`.
- Fixtures use the harmless marker `LEMONINK-MARKER`. Do not add real secrets, working malware, or harmful
  content. Do not paste attack strings from other datasets without checking and stating their license.
- Run `python -m pytest` before sending a pull request.
