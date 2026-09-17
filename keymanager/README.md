# KeyManager

KeyManager provides cryptographic key custody and protection services for Confidential Space.

## Cloning and Submodules

This repository contains git submodules (including BoringSSL for KeyManager). When cloning the repository, clone recursively:

```bash
git clone --recursive https://github.com/google/go-tpm-tools.git
```

If you already cloned without `--recursive`, initialize and update all submodules before building:

```bash
git submodule update --init --recursive
```

## Building KeyManager

Building the KeyManager Rust crates and Go modules requires CMake, Clang, Rust, and initialized git submodules:

```bash
cd keymanager
cargo build --release
```

## Testing

To run the KeyManager Go tests:

```bash
go test ./keymanager/...
```
