# Contributing

ZT-Slop is intentionally small. Before adding a dependency, ask whether the rule can be implemented with the standard library or by invoking an optional external tool.

## Development

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile zt_slop.py
```

## Rule guidelines

A default blocking rule should be:

- deterministic
- explainable
- tied to a PR-introduced change
- unlikely to require executing code
- unlikely to create noisy false positives

Warnings can be broader. Every finding should include evidence and a concrete fix.
