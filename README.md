# Agent PreShip Guard (v1.1)

A free GitHub Action that flags risky AI-agent code before it ships: model output reaching a shell, `eval` on dynamic content, hardcoded keys, `shell=True` tools, secrets in prompts, open URL-fetch tools, and auto-approve flags.

```yaml
# .github/workflows/agent-guard.yml
name: agent-guard
on: [pull_request, push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: elaysuu/agent-preship-guard@v1
        with:
          path: .
          fail-on: high   # high | medium | none
```

Findings show up as inline PR annotations.

## Rules
| ID | Severity | Checks for |
|---|---|---|
| AG001 | high | LLM output passed to subprocess/os.system |
| AG002 | high | eval/exec on non-literal input |
| AG003 | high | Hardcoded OpenAI/AWS/GitHub keys |
| AG004 | medium | `shell=True` |
| AG005 | medium | Env secrets interpolated into prompts |
| AG006 | medium | Fetch tool taking arbitrary URLs (SSRF) |
| AG007 | medium | Auto-approve / skip-confirmation flags |
| AG008 | high | Model/LLM output (e.g. `json.loads(plan)`, `tool_calls`) selects a destructive call (`rmtree`, `os.remove`, `subprocess`, `DROP TABLE`, `DELETE FROM`, `.delete(`, `transfer(`) and no approval/confirm/human-in-the-loop check appears in the file |

These are heuristics. They catch obvious mistakes, not every risk. AG008 is file-level: an approval check in another module will not be seen (possible false positive), and a gate named something other than approve/confirm/hitl/input() will not be recognized.

**v1.1:** fixed an AG001 false positive (`capture_output=True` was read as "model output"), added AG008. Tests: `python3 -m unittest discover -s tests`. See [CHANGELOG.md](CHANGELOG.md).

## Go deeper
- 20 free prompt-injection payloads: https://github.com/elaysuu/prompt-injection-test-payloads
- [AI Agent Pre-Ship Security Checklist (40 checks + tracker)](https://setrov.gumroad.com/l/vldkkl)
- [Prompt-Injection Red-Team Test Pack (100 payloads)](https://setrov.gumroad.com/l/scrwq)
- [MCP Server Security Review Checklist](https://setrov.gumroad.com/l/rxdvi)

If this saved you a bad deploy, consider [sponsoring](https://github.com/sponsors/elaysuu).

MIT licensed.
