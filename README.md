# NZCP.c
An implementation of the NZCP spec in C. Uses TinyCBOR and Sweet B.

Not production ready. Stability or memory safety is not guaranteed.

Contributions welcome! 🥳

## Installation
- Install https://github.com/intel/tinycbor as a system library
- Install https://github.com/westerndigitalcorporation/sweet-b as a system library
- `make`
- `DYLD_LIBRARY_PATH=$PWD/compiled/usr/local/lib ./main`

## License
MIT

## Roadmap
Depends on my availability, but would be nice to:
- Validate CWT claims
- Specify public key as `x` and `y` base64 encoded values
- Enforce C99 standard
- Define an API on how to use the library
- Package as a library
