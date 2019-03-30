# Go-TPM tools

This repository contains various libraries and command line tools designed for
use with [Go-TPM](https://github.com/google/go-tpm):
  - [simulator](https://godoc.org/github.com/google/go-tpm-tools/simulator):
    a Go library allowing the
    [IBM TPM2 simulator](https://sourceforge.net/projects/ibmswtpm2/)
    to be used with Go-TPM.
  - [tpm2tools](https://godoc.org/github.com/google/go-tpm-tools/tpm2tools):
    a Go library providing useful abstractions and utility functions for using a
    TPM2. The goal of this library is to handle complex TPM functionality
    (sessions, authorization, activating credentials, etc...), providing users
    with a simplified API.
  - `flush_handles`: a command line tool that flushes active TPM2 handles.
    Sometimes, TPM commands will leave handles active after they have completed.
    This can cause subsequent TPM commands to fail as only a fixed number
    (usually three) of handles can be active at a given time. Flushing handles
    with this tool allows users to address this problem with out rebooting
    their machine.
  - `get_key`: a command line tool for querying TPM2 public keys. This tool can
    use either the default key template or a template in NVRAM to retrieve PEM
    formatted public keys specific to a user's TPM.

## Legal

Copyright 2018 Google Inc. under the
[Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0). IBM simulator
code is licensed under a [3-clause BSD license](https://opensource.org/licenses/BSD-3-Clause) and the [TCG software license](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf). See the `LICENSE` file for more information.

This is not an official Google product.