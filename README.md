# RustCryptFS
An implementation of [gocryptfs](https://github.com/rfjakob/gocryptfs) in Rust.

## Supported plaforms and features
- [x] Linux (via FUSE)
    - [x] read
    - [ ] write
- [x] Windows
    - [x] read
    - [ ] write

## Features
- mount\
    Allow to mount a virtual filesystem on linux or windows (unimplemented). This feature is no-op on other targets.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.