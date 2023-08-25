use galileo_osnma::galmon::{navmon::nav_mon_message::GalileoInav, transport::ReadTransport};
use galileo_osnma::{
    types::{InavWord, OsnmaDataMessage},
    Gst, InavBand, Wn,
};
use std::error::Error;
use std::io::{BufRead, BufReader};

struct Serial {
    writer: Box<dyn serialport::SerialPort>,
    reader: BufReader<Box<dyn serialport::SerialPort>>,
}

impl Serial {
    fn new(port: &str) -> Result<Serial, Box<dyn Error>> {
        let port = serialport::new(port, 115_200)
            .timeout(std::time::Duration::from_secs(3600))
            .open()?;
        let writer = port.try_clone()?;
        let reader = BufReader::new(port);
        Ok(Serial { writer, reader })
    }

    fn read_until_ready(&mut self) -> Result<(), Box<dyn Error>> {
        loop {
            let mut line = String::new();
            self.reader.read_line(&mut line)?;
            print!("{}", line);
            if line == "READY\r\n" {
                return Ok(());
            }
        }
    }

    fn send_common(&mut self, svn: usize, gst: Gst, band: InavBand) -> Result<(), Box<dyn Error>> {
        let band = match band {
            InavBand::E1B => "1",
            InavBand::E5B => "5",
        };
        write!(
            &mut self.writer,
            "{} {} {} {} ",
            svn,
            gst.wn(),
            gst.tow(),
            band,
        )?;
        Ok(())
    }

    fn send_inav(
        &mut self,
        inav: &InavWord,
        svn: usize,
        gst: Gst,
        band: InavBand,
    ) -> Result<(), Box<dyn Error>> {
        self.send_common(svn, gst, band)?;
        write!(&mut self.writer, "{}\r\n", hex::encode(inav))?;
        Ok(())
    }

    fn send_osnma(
        &mut self,
        osnma: &OsnmaDataMessage,
        svn: usize,
        gst: Gst,
        band: InavBand,
    ) -> Result<(), Box<dyn Error>> {
        self.send_common(svn, gst, band)?;
        write!(&mut self.writer, "{}\r\n", hex::encode(osnma))?;
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    let port = &args[1];
    let mut serial = Serial::new(port)?;
    let mut read_galmon = ReadTransport::new(std::io::stdin());

    loop {
        let packet = read_galmon.read_packet()?;
        if let Some(
            inav @ GalileoInav {
                contents: inav_word,
                reserved1: osnma_data,
                sigid: Some(sigid),
                ..
            },
        ) = &packet.gi
        {
            // This is needed because sometimes we can see a TOW of 604801
            let secs_in_week = 604800;
            let tow = inav.gnss_tow % secs_in_week;
            let wn = Wn::try_from(inav.gnss_wn).unwrap()
                + Wn::try_from(inav.gnss_tow / secs_in_week).unwrap();
            let gst = Gst::new(wn, tow);
            let svn = usize::try_from(inav.gnss_sv).unwrap();
            let band = match sigid {
                1 => InavBand::E1B,
                5 => InavBand::E5B,
                _ => {
                    continue;
                }
            };

            serial.read_until_ready()?;
            serial.send_inav(inav_word[..].try_into().unwrap(), svn, gst, band)?;
            if let Some(osnma_data) = osnma_data {
                serial.read_until_ready()?;
                serial.send_osnma(osnma_data[..].try_into().unwrap(), svn, gst, band)?;
            }
        }
    }
}
