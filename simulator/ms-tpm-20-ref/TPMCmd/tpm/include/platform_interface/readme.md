# TPM Platform Interface

- [TPM Platform Interface](#tpm-platform-interface)
- [Description](#description)

# Description

This folder contains headers for the platform interface (functions and data) between the `Core` TPM library and the implementor-provided `Platform` library.
Observe that the interfaces are directional.

| Filename                    | Purpose                                              |
| :-------------------------- | :--------------------------------------------------- |
| tpm_to_platform_interface.h | Functional interface `Core` requires from `Platform` |
| platform_to_tpm_interface.h | Functional interface `Core` exposes to `Platform`    |
