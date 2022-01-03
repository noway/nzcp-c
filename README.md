# NZCP.c
An implementation of the [NZ COVID Pass](https://github.com/minhealthnz/nzcovidpass-spec) spec in C. Uses [TinyCBOR](https://github.com/intel/tinycbor) and [Sweet B](https://github.com/westerndigitalcorporation/sweet-b).

Features
- A fully implemented NZCP spec
- A defined API (experimental)
- The code that is packaged as a library

Contributions welcome! 🥳

## API
```c
  // initiate verification result on stack
  nzcp_verification_result verification_result;

  // verify pass
  // last argument determines if it's example or live MOH DID document
  int error = nzcp_verify_pass_uri(PASS_URI, &verification_result, 1);

  // check for error
  if (error == NZCP_E_SUCCESS) {
    printf("jti: %s\n", verification_result.jti);
    printf("iss: %s\n", verification_result.iss);
    printf("nbf: %d\n", verification_result.nbf);
    printf("exp: %d\n", verification_result.exp);
    printf("given_name: %s\n", verification_result.given_name);
    printf("family_name: %s\n", verification_result.family_name);
    printf("dob: %s\n", verification_result.dob);
  }
  else {
    printf("error: %s\n", nzcp_error_string(error));
  }

  // free memory of verification result properties
  nzcp_free_verification_result(&verification_result);
```

See [example/](example/) for more.

## Requirements
- Development Tools (gcc or clang, etc)
- `cmake` v3
- `unzip`

## Installation
To install the library and the includes:
- Run `make`
- Run `make install` to install globally or `DESTDIR=$PWD/mydir make install` to install locally

## Binary size
[example/main.c](example/main.c) executable compiles to 95Kb on macOS 12 with `-O3` using Clang.

## Caveats
- Stability or memory safety is not fully guaranteed - best effort is made, but C is a language with an unsafe memory model.
- The library was not audited.
- The library was not fuzzed.

## Java integration 
See [jni/](jni/).
## Tests
See [tests/](tests/).

## Roadmap
Depends on my availability, but would be nice to:
- Specify public key as `x` and `y` base64 encoded values
- Check in Valgrind
- Online DID fetching using CURL

## License
MIT
