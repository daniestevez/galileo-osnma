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
library in some embedded microcontrollers. A demo of galileo-osnma running in a
[Longan nano](https://longan.sipeed.com/en/) GD32VF103 board is provided in the
[osnma-longan-nano](https://github.com/daniestevez/galileo-osnma/tree/main/osnma-longan-nano)
crate. This is a RISC-V microcontroller with 128 KiB of flash and 32 KiB of RAM
that is similar to the popular STM32F103 ARM Cortex-M3 microcontroller.

## Documentation

The documentation for galileo-osnma is hosted in
[docs.rs](https://docs.rs/galileo-osnma/).

The following reference documents from the Galileo system are relevant:

* [Galileo OS SIS ICD v2.0](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OS_SIS_ICD_v2.0.pdf)

* [Galileo OSNMA SIS ICD v1.0](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.0.pdf)

* [Galileo OSNMA Receiver Guidelines v1.0](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_Receiver_Guidelines_v1.0.pdf)

## Quick start using Galmon

galileo-osnma comes with a small binary application that can read Galileo INAV
pages using the [Galmon](https://github.com/berthubert/galmon) [transport
protocol](https://github.com/berthubert/galmon#internals). This is located in
the `galmon-osnma` folder.

A quick way to see this working is to use the Galmon Galileo navigation data
feed, which streams from 86.82.68.237, TCP port 10000. From the `galmon-osnma`
folder, we can run
```
nc 86.82.68.237 10000 | RUST_LOG=info cargo run --release osnma-pubkey.pem
```
to see galileo-osnma processing the OSNMA and navigation data streamed by Galmon.
The [env_logger](https://docs.rs/env_logger/latest/env_logger/) documentation describes
how the logging information produced by this application can be configured.

The file `osnma-pubkey.pem` should contain the Galileo OSNMA public key. See the
section below for how to obtain the key.

Note that Galmon aggregates data from many receivers around the world, which is
not the expected use case for galileo-osnma. Therefore, when running this,
there can be some small problems with data or timestamps inconsistencies.

Alternatively, you can use one of the tools of Galmon with your own GNSS
receiver. For instance, an uBlox receiver can be used as
```
ubxtool --wait --port /dev/ttyACM0 --station 1 --stdout --galileo | RUST_LOG=info cargo run --release osnma-pubkey.pem
```

## Obtaining the Galileo OSNMA public key

The OSNMA ECDSA public key needs to be obtained to run `galmon-osnma` and other
example applications, as well as to make full use of the library. The key can be
downloaded from the [European GNSS Service Centre](https://www.gsc-europa.eu/),
under [GSC Products > OSNMA_PUBLICKEY](https://www.gsc-europa.eu/gsc-products/OSNMA/PKI).
It is necessary to register an account to obtain the key.

The key is downloaded in an x509 certificate. The current certificate file is
`OSNMA_PublicKey_20230803105952_newPKID_1.crt`. The key in PEM format, as
required by `galmon-osnma` can be extracted with
```
openssl x509 -in OSNMA_PublicKey_20230803105952_newPKID_1.crt  -noout -pubkey > osnma-pubkey.pem
```

## Development status

galileo-osnma has been usable since its first release during the public test
phase of OSNMA, and now that the service phase has begun. phase of OSNMA. It
can authenticate all the types of navigation data currently supported by OSNMA
using the ECDSA P-256 public key. There are some features of the OSNMA protocol
and some roadmap features that are not implemented yet. These are listed below.

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
  elliptic curve is needed. This curve is currently not in use by the Galileo
  OSNMA service phase.
* Public key renewal. The parsing of DSM-PKR messages and the authentication
  using the Merkle tree is not implemented yet.
* Change of TESLA chain scenarios. Currently it is assumed that there is only
  one TESLA chain being used. The handling of the scenarios defined in Section
  5.5 of the [Galileo OSNMA SIS ICD v1.0](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.0.pdf)
  is not implemented.
* Flexible ADKDs in the MAC look-up table. These are not currently defined for
  in the [Galileo OSNMA SIS ICD v1.0](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.0.pdf).
* Warm start, by loading a previously authenticated TESLA key.

Roadmap features. These are not features of OSNMA itself, but will add to the
functionality and usability of galileo-osnma:

* C API
* Python API

## Minimum Supported Rust Version

Rust **1.70** or higher.

Minimum supported Rust version can be changed in the future, but it will be done
with a minor version bump.

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
