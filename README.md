# Google Merkle tree
This repository contains:
* Google code for a C++ Merkle tree
* C bindings for the C++ tree
* A Rust library that interfaces with the C bindings

The intent is that the Rust library can be used to create a web server providing the Merkle tree
as a service, avoiding the difficulty of writing such a service in C++.

## Building
Ensure you have the required libraries and tools:
* libssl
* libc++
* clang
* Rust

Run `make` to build the C++ project and create the C static library, then navigate to the `rust/`
directory and run `cargo test` to build the Rust library and run tests.
