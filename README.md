# Go-TPM tools

This repository contains various libraries and a command line tool designed for
use with [Go-TPM](https://github.com/google/go-tpm):
  - [simulator](https://godoc.org/github.com/google/go-tpm-tools/simulator):
    Go bindings to the Microsoft's
    [TPM2 simulator](https://github.com/Microsoft/ms-tpm-20-ref/).
  - [tpm2tools](https://godoc.org/github.com/google/go-tpm-tools/tpm2tools):
    a Go library providing useful abstractions and utility functions for using a
    TPM2. The goal of this library is to handle complex TPM functionality
    (sessions, authorization, activating credentials, etc...), providing users
    with a simplified API.
  - `gotpm`: a command line tool for using the TPM from the command line. Run
    `gotpm --help` and `gotpm [command] --help` for more documentation.

## Minimum Required Go Version

This project currently requires Go 1.13 or newer. In general, we try to support
building with all [currently supported Go versions](https://endoflife.date/go).
Any update to the minimum required Go version will be released as a **minor**
version update.

## macOS Dev
macOS fails to `go build` and `go test` by default with the error `ld: library not found for -lcrypto`.
Fix it by installing OpenSSL and pointing cgo to the include and lib.

These commands were tested on macOS 10.15.7 (Catalina).
### Install OpenSSL
1. Install Homebrew
1. `brew install openssl`
1. `cd /usr/local/include`
1. `sudo ln -s  $(brew --prefix openssl)/include/openssl .`

To point the simulator at openssl as provided by Homebrew, there are a couple
of options. Both of these use the output of `$(brew --prefix openssl)` for
`$OPENSSL_PATH`.

#### Add OpenSSL to the include and library path at the commandline
This solution does not require modifying go-tpm-tools code and is useful when
working on other projects that depend on go-tpm-tools/simulator.
```
C_INCLUDE_PATH="$OPENSSL_PATH/include" LIBRARY_PATH="$OPENSSL_PATH/lib" go test ...
```

#### Add OpenSSL to the include and library path in the code
This solution modifies your local copy of the go-tpm-tools simulator source
and removes the need to provide the paths on the commandline.

Remember to remove the lines from `simulator/internal/internal.go` before
committing changes.
```
// #cgo CFLAGS: -I $OPENSSL_PATH/include
// #cgo LDFLAGS: -L$OPENSSL_PATH/lib
```

## Legal

Copyright 2018 Google Inc. under the
[Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0). Microsoft's TPM simulator
code is licensed under a [3-clause BSD license](https://opensource.org/licenses/BSD-3-Clause) and the [TCG software license](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf). See the `LICENSE` file for more information.

This is not an official Google product.
