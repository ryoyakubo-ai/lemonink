# lemonink

[日本語](README.ja.md)

> Prototype (v0.0.1). Rules and output format will change.

Offline safety checks for [Model Context Protocol](https://modelcontextprotocol.io) servers, with first-class
support for **Japanese**. The name comes from lemon-juice invisible ink: writing that stays hidden until you heat the paper. lemonink brings hidden instructions to the surface.

It looks for:

- **Poisoned descriptions**: hidden instructions to the model in tool, parameter, prompt and resource
  descriptions and in server `instructions` — written in Japanese or English.
- **Obfuscation**: full-width letters, half-width katakana, katakana-spelled English, zero-width and
  bidirectional characters, Unicode tag characters, Latin/Cyrillic homoglyphs. Text is NFKC-normalized
  before matching, and a match that appears only after normalization is reported as obfuscated and
  raised one severity level.
- **Broad permissions**: shell execution, file write/delete, arbitrary URLs, unconstrained
  `command` / `path` / `url` parameters, and annotations that contradict the tool (`readOnlyHint: true`
  on a shell tool).
- **Risky client configs**: unpinned `npx`/`uvx` packages, plain-text tokens, `http://` remotes,
  privileged containers, whole-home or root paths, `curl | sh`.
- **Changes since last time** (rug pulls): `--save-baseline` / `--baseline` hash every definition.

## Why another scanner?

Many existing MCP scanners focus on English patterns, or send tool descriptions to a remote API or an LLM for analysis.
lemonink is different in two ways:

1. **Japanese and CJK-aware.** Poisoning written in Japanese, or English hidden with full-width letters
   or katakana, passes English-only rules. The rules here are built from the same Japanese rewriting
   patterns measured in [jp-inject](https://github.com/ryoyakubo-ai/jp-inject).
2. **Fully local.** No network calls, no LLM, no dependencies beyond the Python standard library.
   Nothing about your servers leaves your machine.

## Install and run

```bash
pip install -e .            # Python 3.10+
lemonink tools tools_list.json                  # a saved tools/list result
lemonink config ~/.cursor/mcp.json              # check a client config (reads only)
lemonink config claude_desktop_config.json --connect   # also start each stdio server and list its tools
lemonink stdio -- npx -y some-server@1.2.3      # start one stdio server and scan it
```

Options: `--format text|json|sarif`, `--fail-on high|medium|low|never` (exit code 1 when a finding is at
or above this level), `--min-severity`, `--save-baseline FILE`, `--baseline FILE`.

`--connect` and `stdio` **run the server's code** on your machine, exactly like your MCP client would.
lemonink only calls `initialize` and the `*/list` methods; it never calls a tool. Scan untrusted servers
in a sandbox or container.

## Limits

Pattern rules find known shapes of attack. They miss new phrasings and can flag harmless text
(`【重要】` is common in normal Japanese writing, so it is only `low`). A clean result is not proof that a
server is safe. Streamable HTTP servers are not supported yet; save their `tools/list` output and use
`lemonink tools`.

## Responsible use

This is a defensive tool. Test fixtures show attacks only with a harmless marker (`LEMONINK-MARKER`).
Please report false negatives and false positives as issues, without real secrets.

## License

Apache-2.0
