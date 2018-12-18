# Private Cryptocurrency Service

[![Travis Build Status](https://img.shields.io/travis/com/exonum/private-currency/master.svg?label=Linux%20Build)](https://travis-ci.com/exonum/private-currency) 
[![License: Apache-2.0](https://img.shields.io/github/license/exonum/private-currency.svg)](https://github.com/exonum/private-currency/blob/master/LICENSE) 
![nightly rust required](https://img.shields.io/badge/rust-nightly--2018--11--13+-orange.svg)

**Documentation:** [![crate docs (master)](https://img.shields.io/badge/master-yellow.svg?label=docs)][crate-doc]

This is an [Exonum] service implementing a privacy-preserving cryptocurrency. The service hides the amounts being
transferred among registered accounts (but not the identities of transacting accounts).

Behind the scenes, the service uses [the Rust implementation][bulletproofs-rs] of [Bulletproofs], a particular
type of zero-knowledge proofs.

**Warning.** This is a proof of concept; it has not been tested and fitted for production. Use at your own risk.

## Description

See [implementation details](docs/implementation.md) and [service crate docs][crate-doc].

## Building and testing

Notice that the service requires `nightly` Rust channel as of now; the `bulletproofs` crate doesn’t build otherwise.
There are some unit and integration tests and also examples. See their documentation for more details.

## License

Licensed under the Apache License (Version 2.0). See [LICENSE](LICENSE) for details.

[Exonum]: https://exonum.com/
[bulletproofs-rs]: https://doc.dalek.rs/bulletproofs/
[Bulletproofs]: https://eprint.iacr.org/2017/1066.pdf
[crate-doc]: https://exonum.github.io/private-currency/private_currency/
