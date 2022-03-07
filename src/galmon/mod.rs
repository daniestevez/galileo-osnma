pub mod navmon {
    include!(concat!(env!("OUT_DIR"), "/navmon_protobuf.rs"));
}

pub mod transport {
    use super::navmon::NavMonMessage;
    use bytes::BytesMut;
    use prost::Message;
    use std::io::Read;

    pub struct ReadTransport<R> {
        read: R,
        buffer: BytesMut,
    }

    impl<R: Read> ReadTransport<R> {
        pub fn new(read: R) -> ReadTransport<R> {
            let default_cap = 2048;
            let mut buffer = BytesMut::with_capacity(default_cap);
            buffer.resize(default_cap, 0);
            ReadTransport { read, buffer }
        }

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
    }
}
