use galileo_osnma::galmon::{
    navmon::nav_mon_message::GalileoInav,
    transport::{ReadTransport, WriteTransport},
};

fn main() -> std::io::Result<()> {
    let mut read = ReadTransport::new(std::io::stdin());
    let mut write = WriteTransport::new(std::io::stdout());

    loop {
        let packet = read.read_packet()?;
        if let Some(GalileoInav { .. }) = &packet.gi {
            write.write_packet(&packet)?;
        }
    }
}
