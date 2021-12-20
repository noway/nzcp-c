# NZCP.c
An implementation of the NZCP spec in C. Uses TinyCBOR and Sweet B.

Not production ready. Stability or memory safety is not guaranteed.

Contributions welcome! 🥳

## Requirements
- Development Tools (gcc or clang, etc)
- `cmake` v3
- `git`

## Installation
- `make`
- `./main`

## License
MIT

## Roadmap
Depends on my availability, but would be nice to:
- Validate CWT claims
- Specify public key as `x` and `y` base64 encoded values
- Enforce C99 standard
- Define an API on how to use the library
- Package as a library