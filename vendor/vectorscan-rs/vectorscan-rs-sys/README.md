# `vectorscan-rs-sys`


## Overview
This crate implements minimal Rust bindings to the [Vectorscan](https://github.com/Vectorcamp/vectorscan) fork of [Hyperscan](https://github.com/intel/hyperscan), the high-performance regular expression engine.
This crate builds a vendored copy of Vectorscan from source.


## Dependencies
- [Boost](https://boost.org) >= 1.57
- [CMake](https://cmake.org)
- Optional: [Clang](https://clang.llvm.org), when building with the `bindgen` feature

This has been tested on x86_64 Linux, x86_64 macOS, and aarch64 macOS.


## Implementation Notes
This crate was originally written as part of [Nosey Parker](https://github.com/praetorian-inc/noseyparker).
It was adapted from the [pyperscan](https://github.com/vlaci/pyperscan) project, which uses Rust to expose Hyperscan to Python.
(That project is released under either the Apache 2.0 or MIT license.)

The only bindings exposed at present are for Vectorscan's block-based matching APIs.
The various other APIs such as stream- and vector-based matching are not exposed.
Other features, such as the Chimera PCRE library, test code, benchmark code, and supporting utilities are disabled.

The source of Vectorscan 5.4.12 is included as an extracted source directory in [`vectorscan/`](vectorscan/).


## License
This project is licensed under either of

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
  ([LICENSE-APACHE](../LICENSE-APACHE))

- [MIT License](https://opensource.org/licenses/MIT)
  ([LICENSE-MIT](../LICENSE-MIT))

at your option.

This project contains a vendored copy of [Vectorscan](https://github.com/Vectorcamp/vectorscan), which is released under a 3-clause BSD license ([LICENSE-VECTORSCAN](../LICENSE-VECTORSCAN)).


## Contributing
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in `vectorscan-rs-sys` by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
