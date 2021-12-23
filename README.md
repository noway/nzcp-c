# NZCP.c
An implementation of the NZCP spec in C. Uses TinyCBOR and Sweet B.

Not production ready. Stability or memory safety is not guaranteed.

Contributions welcome! 🥳

## Example
- `cd example`
- `make`
- `./main`

```bash
$ ./main
error: 0
jti: urn:uuid:60a4f54d-4e30-4332-be33-ad78b1eafa4b
iss: did:web:nzcp.covid19.health.nz
nbf: 1635883530
exp: 1951416330
given_name: Jack
family_name: Sparrow
dob: 1960-04-16
```
## Requirements
- Development Tools (gcc or clang, etc)
- `cmake` v3
- `git`

## Installation
To install `libnzcp.a` and `nzcp.h`:
- Run `make`
- Run `make install` to install globally or `DESTDIR=$PWD/mydir make install` to install locally

## License
MIT

## Roadmap
Depends on my availability, but would be nice to:
- Specify public key as `x` and `y` base64 encoded values
- Enforce C99 standard
- GNU/Linux support
- Tests