# galileo-osnma

[![Crates.io][crates-badge]][crates-url]
[![Rust](https://github.com/daniestevez/galileo-osnma/actions/workflows/rust.yml/badge.svg)](https://github.com/daniestevez/galileo-osnma/actions/workflows/rust.yml)

[crates-badge]: https://img.shields.io/crates/v/galileo-osnma.svg
[crates-url]: https://crates.io/crates/galileo-osnma

galileo-osnma is a Rust implementation of the Galileo OSNMA (Open Service
Navigation Message Authentication) protocol. This protocol is used by the
Galileo GNSS to sign cryptographically the navigation message data transmitted
by its satellites, in order to prevent spoofing. Briefly speaking, galileo-osnma
can process the navigation message data and OSNMA cryptographic data and check
all the cryptographic signatures against the ECDSA public key, in order to check
the authenticity of the navigation data.

galileo-osnma does not require the Rust Standard library (it can be built with
`no_std`), allocates all its data statically on the stack, and has a relatively
small memory footprint for the data (~65 KiB if Slow MAC is used and data for 36
satellites in parallel is stored, and ~7 KiB if Slow MAC is not used and data
for only 12 satellites in parallel is stored). This makes it possible to use the
library in some embedded microcontrollers.

## Documentation

The documentation for galileo-osnma is hosted in
[docs.rs](https://docs.rs/galileo-osnma/).

The following reference documents from the Galileo system are relevant:

* [Galileo OS SIS ICD v2.0](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OS_SIS_ICD_v2.0.pdf)

* [Galileo OSNMA User ICD for Test Phase v1.0](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf)

* [Galileo OSNMA Receiver Guidelines for Test Phase v1.0](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_Receiver_Guidelines_for_Test_Phase_v1.0.pdf)

## Quick start using Galmon

galileo-osnma comes with a small binary application that can read Galileo INAV
pages using the [Galmon](https://github.com/berthubert/galmon) [transport
protocol](https://github.com/berthubert/galmon#internals). This is located in
the `galmon-osnma` folder.

A quick way to see this working is to use the Galmon Galileo navigation data
feed, which streams from 86.82.68.237, TCP port 10000. From the `galmon-osnma`
folder, we can run
```
nc 86.82.68.237 10000 | RUST_LOG=info cargo run --release OSNMA_PublicKey_20210920133026.pem
```
to see galileo-osnma processing the OSNMA and navigation data streamed by Galmon.
The [env_logger](https://docs.rs/env_logger/latest/env_logger/) documentation describes
how the logging information produced by this application can be configured.

Note that Galmon aggregates data from many receivers around the world, which is
not the expected use case for galileo-osnma. Therefore, when running this,
there can be some small problems with data or timestamps inconsistencies.

Alternatively, you can use one of the tools of Galmon with your own GNSS
receiver. For instance, an uBlox receiver can be used as
```
ubxtool --wait --port /dev/ttyACM0 --station 1 --stdout --galileo | RUST_LOG=info cargo run --release OSNMA_PublicKey_20210920133026.pem
```

The OSNMA ECDSA public key needs to be obtained to run this application. This
can be downloaded from the
[European GNSS Service Centre](https://www.gsc-europa.eu/)
by
[registering to the public observation test phase](https://www.gsc-europa.eu/support-to-developers/osnma-public-observation-test-phase/register).
The registration takes a few days to be verified. The PEM file should only contain
the public key, and not the elliptic curve parameters (the PEM file should only contain the
`-----BEGIN PUBLIC KEY-----` line, the `-----END PUBLIC KEY-----` line, and the Base64
data between these two lines).

## Development status

galileo-osnma already provides a solution that is usable during the puublic test
phase of OSNMA. It can authenticate all the types of navigation data currently
supported by OSNMA using the ECDSA P-256 public key. There are some
features of the OSNMA protocol and some roadmap features that are not
implemented yet. These are listed below.

Supported features:

* Verification of DSM-KROOT using ECDSA P-256.
* Verification of TESLA keys using the TESLA root key or another previously
  authenticated key in the chain.
* Verification of the MACSEQ and ADKD fields of the MACK message using the MAC
  look-up table.
* Verification of navigation data for ADKD=0, ADKD=4 and ADKD=12 using all the
  tags in the MACK messages.
* Retrieval of DSM messages using OSNMA data.
* Retrieval of MACK messages using OSNMA data.
* Navigation data retrieval using INAV words.
* Storage of the current TESLA key.
* Storage and classification of MACK messages and navigation data.
* Tag accumulation. 80 bit worth of tags are required to consider a piece
  of navigation data as authenticated.

Unsupported features:

* Verification of DSM-KROOT using ECDSA P-521. A Rust implementation of this
  elliptic curve is needed. This curve is currently not being used in the public test
  phase of OSNMA.
* Public key renewal. The parsing of DSM-PKR messages and the authentication
  using the Merkle tree is not implemented yet.
* Change of TESLA chain scenarios. Currently it is assumed that there is only
  one TESLA chain being used. The handling of the scenarios defined in Section
  5.5 of the
  [OSNMA User ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf)
  is not implemented.
* Flexible ADKDs in the MAC look-up table. These are not currently defined for
  the OSNMA test phase.
* Warm start, by loading a previously authenticated TESLA key.

Roadmap features. These are not features of OSNMA itself, but will add to the
functionality and usability of galileo-osnma:

* C API
* Python API

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
