# AIOS

A personal, AI-driven, security-focused Linux distribution (Arch-based) with
NixOS-style guarantees: read-only generations, an impermanent root, and a
declarative manifest as the only way to change the system.

- Vision: `docs/superpowers/specs/2026-11-03-aios-vision.md`
- Base ISO design: `docs/superpowers/specs/2026-11-03-base-iso-design.md`
- Plans: `docs/superpowers/plans/`

## Development

```bash
make check   # fmt + clippy + unit tests, no root needed
```
