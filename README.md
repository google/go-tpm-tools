# Go-TPM tools

The `go-tpm-tools` module is a [TPM 2.0](https://trustedcomputinggroup.org/resource/trusted-platform-module-2-0-a-brief-introduction/) support library designed to complement [Go-TPM](https://github.com/google/go-tpm).

It contains the following public packages:
  - [`client`](https://pkg.go.dev/github.com/google/go-tpm-tools@v0.3.0-alpha/client):
    A Go package providing simplified abstractions and utility functions for interacting with a TPM 2.0, including:
      - Signing
      - Attestation
      - Reading PCRs
      - Sealing/Unsealing data
      - Importing Data and Keys
      - Reading NVData
      - Getting the TCG Event Log
  - [`server`](https://pkg.go.dev/github.com/google/go-tpm-tools@v0.3.0-alpha/server):
    A Go package providing functionality for a remote server to send, receive, and interpret TPM 2.0 data. None of the commands in this package issue TPM commands, but instead handle:
      - TCG Event Log parsing
      - Attestation verification
      - Creating data for Importing into a TPM
  - [`proto`](https://pkg.go.dev/github.com/google/go-tpm-tools@v0.3.0-alpha/proto):
    Common [Protocol Buffer](https://developers.google.com/protocol-buffers) messages that are exchanged between the `client` and `server` libraries. This package also contains helper methods for validating these messages.
  - [`simulator`](https://pkg.go.dev/github.com/google/go-tpm-tools@v0.3.0-alpha/simulator):
    Go bindings to the Microsoft's [TPM 2.0 simulator](https://github.com/Microsoft/ms-tpm-20-ref/).

This repository also contains `gotpm`, a command line tool for using the TPM.
Run `gotpm --help` and `gotpm <command> --help` for more documentation.

### Building and Installing `gotpm`

`gotpm` can be directly installed from this repo by running:
```bash
go install github.com/google/go-tpm-tools/cmd/gotpm@latest
# gotpm will be installed to $GOBIN
gotpm --help
```
Alternatively, to build `gotpm` from a cloned version of this repo, run:
```bash
cd /my/path/to/cloned/go-tpm-tools
go build ./cmd/gotpm
# gotpm will be in the root of the repo
./gotpm --help
```

## Minimum Required Go Version

This project currently requires Go 1.16 or newer. Any update to the minimum required Go version will be released as a **minor** version update.

## `trousers` errors when building `server`

When building the `server` library (or tests) you may get an error that looks like:
```
fatal error: trousers/tss.h: No such file or directory
   17 | // #include <trousers/tss.h>
      |           ^~~~~~~~~~~~~~~~
compilation terminated.
```
This is because the `server` library (indirectly) depends on the [Trousers `libtspi` library](http://trousers.sourceforge.net/). This is a _temporary_ dependency ([tracking issue](https://github.com/google/go-tpm-tools/issues/109)). To fix this error, install `libtspi` by running:
```bash
sudo apt install libtspi-dev
```

## `openssl` errors when building `simulator`

Similarly, when building the `simulator` library (or tests), you may get an error that looks like:
```
fatal error: openssl/aes.h: No such file or directory
   47 | // #include <openssl/aes.h>
      |           ^~~~~~~~~~~~~~~~
compilation terminated.
```
This is because the `simulator` library depends on having the [OpenSSL](https://www.openssl.org/) headers installed. To fix this error, install them by running:
```bash
sudo apt install libssl-dev
```

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

#### Add OpenSSL to the include and library path at the command line
This solution does not require modifying go-tpm-tools code and is useful when
working on other projects that depend on go-tpm-tools/simulator.
```
C_INCLUDE_PATH="$OPENSSL_PATH/include" LIBRARY_PATH="$OPENSSL_PATH/lib" go test ...
```

#### Add OpenSSL to the include and library path in the code
This solution modifies your local copy of the go-tpm-tools simulator source
and removes the need to provide the paths on the command line.

Remember to remove the lines from `simulator/internal/internal.go` before
committing changes.
```
// #cgo CFLAGS: -I $OPENSSL_PATH/include
// #cgo LDFLAGS: -L$OPENSSL_PATH/lib
```

## No TPM 1.2 support

Unlike [Go-TPM](https://github.com/google/go-tpm) (which supports TPM 1.2 and TPM 2.0), this module explicitly only supports TPM 2.0. Users should avoid use of TPM 1.2 due to the inherent reliance on SHA1 (which is [quite broken](https://sha-mbles.github.io/)).

## Legal

Copyright 2018 Google Inc. under the
[Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0). Microsoft's TPM simulator
code is licensed under a [3-clause BSD license](https://opensource.org/licenses/BSD-3-Clause) and the [TCG software license](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf). See the `LICENSE` file for more information.

This is not an official Google product.
