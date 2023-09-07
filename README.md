# Go-TPM tools [![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/google/go-tpm-tools)](https://github.com/google/go-tpm-tools/releases)

[![Build Status](https://github.com/google/go-tpm-tools/workflows/CI/badge.svg)](https://github.com/google/go-tpm-tools/actions?query=workflow%3ACI)
[![Go Reference](https://pkg.go.dev/badge/github.com/google/go-tpm-tools.svg)](https://pkg.go.dev/github.com/google/go-tpm-tools)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/google/go-tpm-tools)
[![Go Report Card](https://goreportcard.com/badge/github.com/google/go-tpm-tools)](https://goreportcard.com/report/github.com/google/go-tpm-tools)
[![License](https://img.shields.io/badge/LICENSE-Apache2.0-ff69b4.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

The `go-tpm-tools` module is a [TPM 2.0](https://trustedcomputinggroup.org/resource/trusted-platform-module-2-0-a-brief-introduction/) support library designed to complement [Go-TPM](https://github.com/google/go-tpm).

It contains the following public packages:
  - [`client`](https://pkg.go.dev/github.com/google/go-tpm-tools/client):
    A Go package providing simplified abstractions and utility functions for interacting with a TPM 2.0, including:
      - Signing
      - Attestation
      - Reading PCRs
      - Sealing/Unsealing data
      - Importing Data and Keys
      - Reading NVData
      - Getting the TCG Event Log
  - [`server`](https://pkg.go.dev/github.com/google/go-tpm-tools/server):
    A Go package providing functionality for a remote server to send, receive, and interpret TPM 2.0 data. None of the commands in this package issue TPM commands, but instead handle:
      - TCG Event Log parsing
      - Attestation verification
      - Creating data for Importing into a TPM
  - [`proto`](https://pkg.go.dev/github.com/google/go-tpm-tools/proto):
    Common [Protocol Buffer](https://developers.google.com/protocol-buffers) messages that are exchanged between the `client` and `server` libraries. This package also contains helper methods for validating these messages.
  - [`simulator`](https://pkg.go.dev/github.com/google/go-tpm-tools/simulator):
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
cd /my/path/to/cloned/go-tpm-tools/cmd/gotpm
go build
# gotpm will be in the cmd/gotpm subdirectory of the repo
./gotpm --help
```

## Minimum Required Go Version

This project currently requires Go 1.20 or newer. Any update to the minimum required Go version will be released as a **minor** version update.

## `openssl` errors when building `simulator`

Similarly, when building the `simulator` library (or tests), you may get an error that looks like:
```
fatal error: openssl/aes.h: No such file or directory
   47 | // #include <openssl/aes.h>
      |           ^~~~~~~~~~~~~~~~
compilation terminated.
```
This is because the `simulator` library depends on having the [OpenSSL](https://www.openssl.org/) headers installed. To fix this error, install the appropriate header package:

### Linux

```bash
# Ubuntu/Debian based systems
sudo apt install libssl-dev
# Redhat/Centos based systems
sudo yum install openssl-devel
# Arch Linux (headers/library in the same package)
sudo pacman -S openssl
```

### macOS

First, install [Homebrew](https://brew.sh/). Then run:
```bash
brew install openssl
```

### Windows

First, install [Chocolatey](https://chocolatey.org/). Then run:
```bash
choco install openssl
```

### Custom install location

If you want to use a different installation of OpenSSL, or you are getting
linker errors like `ld: library not found for -lcrypto`, you can directly
point Go your installation. We will assume your installation is located at
`$OPENSSL_PATH` (with `lib` and `include` subdirectories).

#### Add OpenSSL to the include and library path at the command line
This solution does not require modifying go-tpm-tools code and is useful when
working on other projects that depend on go-tpm-tools/simulator.
```
C_INCLUDE_PATH="$OPENSSL_PATH/include" LIBRARY_PATH="$OPENSSL_PATH/lib" go test ...
```

#### Add OpenSSL to the include and library path in the code
This solution modifies your local copy of the go-tpm-tools simulator source
and removes the need to provide the paths on the command line.

Modify the `CFLAGS`/`LDFLAGS` options beginning with `#cgo darwin` or
`#cgo windows` in `simulator/internal/internal.go` to point at your
installation. This could look something like:
```diff
// #cgo darwin CFLAGS: -I $OPENSSL_PATH/include
// #cgo darwin LDFLAGS: -L $OPENSSL_PATH/lib
```
Remember to revert your modifications to `simulator/internal/internal.go`
before committing your changes.

## No TPM 1.2 support

Unlike [Go-TPM](https://github.com/google/go-tpm) (which supports TPM 1.2 and TPM 2.0), this module explicitly only supports TPM 2.0. Users should avoid use of TPM 1.2 due to the inherent reliance on SHA1 (which is [quite broken](https://sha-mbles.github.io/)).

## Legal

Copyright 2018 Google Inc. under the
[Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0). Microsoft's TPM simulator
code is licensed under a [3-clause BSD license](https://opensource.org/licenses/BSD-3-Clause) and the [TCG software license](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf). See the [`LICENSE`](LICENSE) file for more information.

This is not an official Google product.
