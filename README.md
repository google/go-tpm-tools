# Go-TPM tools

This repository contains various tools designed for use with
[Go-TPM](https://github.com/google/go-tpm):
  - [simulator](https://godoc.org/github.com/google/go-tpm-tools/simulator):
    Allows the [IBM TPM2 simulator](https://sourceforge.net/projects/ibmswtpm2/)
    to be used with Go-TPM.
  - [tpm2tools](https://godoc.org/github.com/google/go-tpm-tools/tpm2tools):
    Useful abstractions and utility functions for using TPM2. The goal of this
    package is to handle complex TPM functionality (sessions, authorization,
    activating credentials, etc...) for the user, presenting a simplified API.

## Legal

Copyright 2018 Google Inc. under the
[Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0). IBM simulator
code is licensed under a [3-clause BSD license](https://opensource.org/licenses/BSD-3-Clause) and the [TCG software license](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf). See the `LICENSE` file for more information.

This is not an official Google product.