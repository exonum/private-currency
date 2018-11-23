# Private Cryptocurrency Service

This is an [Exonum] service implementing privacy-preserving cryptocurrency. The service hides the amounts being
transferred among registered accounts (but not the identities transacting accounts).

**Warning.** This is a proof of concept; it has not been tested and fitted for production. Use at your own risk.

## Description

See [implementation details](docs/implementation.md).

## Building and testing

Notice that the service requires `nightly` Rust channel as of now; the `bulletproofs` crate doesn't build otherwise.
There are some unit and integration tests and also examples. See their documentation for more details.

## License

Licensed under the Apache License (Version 2.0). See [LICENSE](LICENSE) for details.

[Exonum]: https://exonum.com/
[bulletproofs-rs]: https://doc.dalek.rs/bulletproofs/
[bulletproofs]: https://eprint.iacr.org/2017/1066.pdf
[pedersen]: https://en.wikipedia.org/wiki/Commitment_scheme
[demo]: https://github.com/exonum/exonum/tree/master/examples