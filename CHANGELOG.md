# Changelog

## 0.1.0 (unreleased)

First release on PyPI.

- Poisoned-description rules: 9 Japanese (`JA001`-`JA009`) and 6 English (`EN001`-`EN006`).
- Obfuscation checks after NFKC normalization: full-width letters, half-width katakana,
  katakana-spelled English, zero-width, bidi and Unicode tag characters, Latin/Cyrillic homoglyphs.
- Permission checks (`PERM...`), client-config checks (`CFG...`), baseline hashes (`PIN...`).
- `tools`, `config` (with `--connect`) and `stdio` commands; text, JSON and SARIF output.
