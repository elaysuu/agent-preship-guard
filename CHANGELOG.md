# Changelog

## v1.1 (2026-10-29)
- Fixed: AG001 false positive. `capture_output=True` matched the "output" keyword, so a fixed literal command (`subprocess.run("uptime", ...)`) was reported as LLM output reaching a shell. Keywords now require a word boundary.
- Added: AG008 (high). Flags a file where model/LLM output selects a destructive call (rmtree, os.remove/unlink, subprocess, os.system, DROP TABLE, DELETE FROM, .delete(, transfer() and no approval / confirm / human-in-the-loop check exists. Comments do not count as a gate.
- Added: tests/ (7 unittest cases).
- Found by running our own scanner on two demo agents: v1.0 gave the safe one 1 high + 1 medium and the dangerous one 0 findings.

## v1.0
- Initial rules AG001-AG007.
