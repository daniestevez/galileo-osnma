//! Galmon integration.
//!
//! This module contains a reader for the
//! [Galmon transport protocol](https://github.com/berthubert/galmon#internals).
//! The reader can be used to obtain INAV frames and OSNMA data from the
//! [Galmon](https://github.com/berthubert/galmon) tools, such as `ubxtool`.

pub mod navmon {
    //! Galmon `navmon` protocol buffers definition.
    //!
    //! This module contains a Rust version of the protocol buffers definition
    //! [`navmon.proto`](https://github.com/berthubert/galmon/blob/master/navmon.proto).
    //! The [prost](https://crates.io/crates/prost) crate is used to generate the
    //! code in this module.
    #![allow(missing_docs)]
    include!(concat!(env!("OUT_DIR"), "/navmon_protobuf.rs"));
}

pub mod transport {
    //! Galmon transport protocol.
    use super::navmon::NavMonMessage;
    use bytes::BytesMut;
    use prost::Message;
    use std::io::{Read, Write};

    /// Reader for the Galmon transport protocol.
    ///
    /// This wraps around a [`Read`] `R` and can be used to read navmon packets
    /// from `R`.
    #[derive(Debug, Clone)]
    pub struct ReadTransport<R> {
        read: R,
        buffer: BytesMut,
    }

    impl<R: Read> ReadTransport<R> {
        /// Constructs a new reader using a [`Read`] `read`.
        pub fn new(read: R) -> ReadTransport<R> {
            let default_cap = 2048;
            let mut buffer = BytesMut::with_capacity(default_cap);
            buffer.resize(default_cap, 0);
            ReadTransport { read, buffer }
        }

        /// Tries to read a navmon packet.
        ///
        /// If the read is successful, a navmon packet is returned.
        pub fn read_packet(&mut self) -> std::io::Result<NavMonMessage> {
            // Read 4-byte magic value and 2-byte frame length
            if let Err(e) = self.read.read_exact(&mut self.buffer[..6]) {
                log::error!("could not read packet header: {}", e);
                return Err(e);
            }
            if &self.buffer[..4] != b"bert" {
                let err = "incorrect galmon magic value";
                log::error!("{}", err);
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, err));
            }
            let size = usize::from(u16::from_be_bytes(self.buffer[4..6].try_into().unwrap()));
            if size > self.buffer.len() {
                log::debug!("resize buffer to {}", size);
                self.buffer.resize(size, 0);
            }
            // Read protobuf frame
            if let Err(e) = self.read.read_exact(&mut self.buffer[..size]) {
                log::error!("could not read protobuf frame: {}", e);
                return Err(e);
            }
            let frame = match NavMonMessage::decode(&self.buffer[..size]) {
                Ok(f) => {
                    log::trace!("decoded protobuf frame: {:?}", f);
                    f
                }
                Err(e) => {
                    log::error!("could not decode protobuf frame: {}", e);
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
                }
            };
            Ok(frame)
        }
    }

    /// Writer for the Galmon transport protocol.
    ///
    /// This wraps around a [`Write`] `W` and can be used to write navmon packets
    /// to `W`.
    #[derive(Debug, Clone)]
    pub struct WriteTransport<W> {
        write: W,
        buffer: BytesMut,
    }

    impl<W: Write> WriteTransport<W> {
        /// Constructs a new writer using a [`Write`] `write`.
        pub fn new(write: W) -> WriteTransport<W> {
            let default_cap = 2048;
            let mut buffer = BytesMut::with_capacity(default_cap);
            buffer.reserve(default_cap);
            WriteTransport { write, buffer }
        }

        /// Tries to write a navmon packet.
        ///
        /// If the write is successful, the number of bytes writte is returned.
        pub fn write_packet(&mut self, packet: &NavMonMessage) -> std::io::Result<usize> {
            let size = packet.encoded_len();
            // Header is 6 bytes
            let total_size = size + 6;
            let cap = self.buffer.capacity();
            if total_size > cap {
                log::debug!("resize buffer to {}", total_size);
                self.buffer.reserve(total_size - cap);
            }
            self.buffer.clear();
            self.buffer.extend_from_slice(b"bert");
            let size_u16 = u16::try_from(size).unwrap();
            self.buffer.extend_from_slice(&size_u16.to_be_bytes());
            match packet.encode(&mut self.buffer) {
                Ok(()) => log::trace!("encoded protobuf frame: {:?}", packet),
                Err(e) => {
                    log::error!("could not encoded protobuf frame: {}", e);
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
                }
            };
            match self.write.write_all(&self.buffer) {
                Ok(()) => Ok(self.buffer.len()),
                Err(e) => {
                    log::error!("could not write: {}", e);
                    Err(e)
                }
            }
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        mod data;

        #[test]
        fn read_packets() {
            let packets = &data::GALMON_PACKETS[..];
            let mut transport = ReadTransport::new(packets);
            // There should be 17 packets in the test data
            for _ in 0..17 {
                transport.read_packet().unwrap();
            }
        }

        #[test]
        fn bad_magic() {
            let packets = &data::GALMON_PACKETS[2..];
            let mut transport = ReadTransport::new(packets);
            assert!(transport.read_packet().is_err());
        }

        #[test]
        fn short_packet() {
            let packets = &data::GALMON_PACKETS[..10];
            let mut transport = ReadTransport::new(packets);
            assert!(transport.read_packet().is_err());
        }

        #[test]
        fn read_packets_write_packets() {
            let buffer = Vec::new();
            let packets = &data::GALMON_PACKETS[..];
            let mut read = ReadTransport::new(packets);
            let mut write = WriteTransport::new(buffer);
            let mut total_size = 0;
            // There should be 17 packets in the test data
            for _ in 0..17 {
                let packet = read.read_packet().unwrap();
                total_size += write.write_packet(&packet).unwrap();
            }
            assert_eq!(&write.write, packets);
            assert_eq!(total_size, packets.len());
        }
    }
}
