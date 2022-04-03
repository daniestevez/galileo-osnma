# osnma-longan-nano

This is a demo of the [galileo-osnma](https://github.com/daniestevez/galileo-osnma)
library running in a [Longan nano](https://longan.sipeed.com/en/)
GD32VF103CBT6 board. The GD32VF103CBT6 is a RISC-V microcontroller with 128 KiB
of flash and 32 KiB of RAM. It is similar to the STM32F103 ARM Cortex-M3
microcontroller. This board is well supported in Rust through the
[longan-nano](https://github.com/riscv-rust/longan-nano) BSP crate and
[gd32vf103xx-hal](https://github.com/riscv-rust/gd32vf103xx-hal) HAL crate,
so it is a good board to demonstrate that galileo-osnma can run in small
embedded microcontrollers.

## Usage

### Building

The instructions to set up the Rust riscv32imac toolchain can be found in the
documentation for the [longan-nano](https://github.com/riscv-rust/longan-nano)
crate.

The OSNMA ECDSA P-256 public key is embedded in the binary during the build
process. The public key is taken from the `pubkey.pem` file found in the root
folder of this crate. A "fake" public key is provided so that osnma-longan-demo
can be built without access to the authentic public key. A binary built with
this fake public key will not work with the Galileo signal in space, since
it will not be able to validate the TESLA root key.

The fake `pubkey.pem` needs to be replaced with the authentic key, using the
same PEM file format. Instructions about how to obtain the authentic public key
can be found in the
[galileo-osnma README](https://github.com/daniestevez/galileo-osnma#quick-start-using-galmon).

Once the file `pubkey.pem` contains the authentic public key, the crate can be
built using
```
cargo build --release
```
Note that it is mandatory to build using the `--release` profile, since a binary
built without `--release` will not fit in the 128 KiB of flash, so `rust-lld` will
give an error.

### Flashing

After the binary is built, it can be flashed to the microcontroller using any of
the methods described in the
[longan-nano documentation](https://github.com/riscv-rust/longan-nano#longan-nano).
The easiest method for flashing is using dfu-util. This can be done by running
```
objcopy -O binary target/riscv32imac-unknown-none-elf/release/osnma-longan-nano firmware.bin
dfu-util -a 0 -s 0x08000000:leave -D firmware.bin
```
The `objcopy` command must belong to a riscv toolchain, and when `dfu-util` is run
the microcontroller should be in DFU mode and connected by USB to the computer. DFU
mode is entered by holding the BOOT0 button on the board while the board is powered
on or resetted.

### Serial port connection

The osnma-longan-nano demo uses the UART0 serial port of the GD32VF103 to
communicate with the host computer. The host computer sends INAV frames to the
microcontroller and the microcontroller gives information about the OSNMA
authentication status using the serial port.

The UART0 port is routed to the JTAG pin header. See
[this pinout diagram](https://longan.sipeed.com/assets/longan_nano_pinout_v1.1.0_w5676_h4000_large.png). The pins are identified as RX0 and TX0 in the diagram, and as R0 and T0 in the
silkscreen of the board. The UART port uses 3V3 TTL levels. A suitable UART to USB
converter such as [this device](https://www.amazon.com/gp/product/B07D6LLX19) should typically be used to connect the UART to the host computer.

### Running the serial port client

The serial port client that runs on the host computer can be found in the
[osnma-longan-nano-client](https://github.com/daniestevez/galileo-osnma/tree/main/osnma-longan-nano-client) crate.

The binary in this crate must be run by indicating the path to the computer
serial port to use (for instance `/dev/ttyACM0` or `/dev/ttyUSB0`) and feeding to its
standard input data using the Galmon transport protocol, in the same way as with the
`galmon-osnma` crate (see
[these instructions](https://github.com/daniestevez/galileo-osnma#quick-start-using-galmon)).

The serial port client will send the INAV and OSNMA data to the board and print
to the standard output all the lines received from the microcontroller through
the UART. The UART communication is described below.

So, in the same way that navigation data can be piped to this application running on a local computer ([instructions](https://github.com/daniestevez/galileo-osnma#quick-start-using-galmon)), a web stream or 'live' data from a GNSS receiver can be piped to the [Longan nano](https://longan.sipeed.com/en/) via the [serial port client](https://github.com/daniestevez/galileo-osnma/tree/main/osnma-longan-nano-client).

Example: (run from ~/galileo-osnma/osnma-longan-nano-client/target/release/)
```
nc 86.82.68.237 10000 | ./osnma-longan-nano-client /dev/ttyUSB0
```

After starting the serial port client, the microcontroller should be reset or
powered on to start running the demo.

## Theory of operation

The serial port client and the firmware running in the microcontroller use a
simple ASCII line-based protocol to communicate (the lines are terminated by CRLF).

The client can send an INAV word by sending a line such as
```
19 1176 120939 2a2aaaaaaaaaaaaaaaaaa80327fd4618
```
The first number indicates the SVN (E19), the second number indicates the week number,
the third number indicates the time of week in seconds, and after this the data in the
INAV word is included in hex.

Similarly, OSNMA data is sent by the client with a line such as
```
19 1176 120939 6d0309ba0b
```

The microcontroller indicates to the client that it is ready to receive a new piece
of data (either an INAV page or OSNMA data) by sending the line
```
READY
```
This implements a simple but effective flow control. After successfully receiving
an INAV word, the microcontroller sends back
```
E19 WN 1176 TOW 120939 INAV
```
and after receiving OSNMA data it sends back
```
E19 WN 1176 TOW 120939 OSNMA
```

After receiving any piece of data, the microcontroller also reports the
authentication status of the data it is holding on its storage memory. This is reported as
```
AUTH ADKD=4 TOW 121110
```
indicating that successfully authenticated ADKD=4 corresponding to the subframe TOW 121110
is now available, or as
```
AUTH ADKD=4 NONE
```
reporting that no ADKD=4 in the microcontroller memory is authenticated yet.
Similarly, the ADKD=0 authentication status is reported as
```
AUTH ADKD=0 E18 TOW 121080 E27 TOW 121080
```
by listing the SVNs and TOWs of the data that is authenticated, or
```
AUTH ADKD=0 NONE
```
if the data is currently not authenticated.

The storage memory is sized to be small, according to the small SRAM available
in the microcontroller, so the authentication state alternates between having
some authenticated data and `NONE` as the authenticated data is erased make room
for newer (not yet authenticated) data.

