#![no_std]
#![no_main]

use crate::pac::USART0;
use core::fmt::Write;
use galileo_osnma::{
    storage::SmallStorage,
    types::{HKROOT_SECTION_BYTES, INAV_WORD_BYTES, MACK_SECTION_BYTES},
    Gst, Osnma, Svn,
};
use longan_nano::hal::{pac, prelude::*, serial};
use nb::block;
use p256::ecdsa::VerifyingKey;
use panic_halt as _;
use riscv_rt::entry;

// The OSNMA public key, as a [u8; N] constant, is generated from pubkey.pem in
// the build script and included here.
include!(concat!(env!("OUT_DIR"), "/osnma_pubkey.rs"));

struct Board {
    tx: serial::Tx<USART0>,
    rx: serial::Rx<USART0>,
    rx_buffer: [u8; 256],
}

impl Board {
    fn take() -> Board {
        let p = pac::Peripherals::take().unwrap();
        let mut rcu = p
            .RCU
            .configure()
            .ext_hf_clock(8.mhz())
            .sysclk(108.mhz())
            .freeze();
        let mut afio = p.AFIO.constrain(&mut rcu);
        let gpioa = p.GPIOA.split(&mut rcu);
        let serial = serial::Serial::new(
            p.USART0,
            (gpioa.pa9, gpioa.pa10),
            serial::Config::default().baudrate(115_200.bps()),
            &mut afio,
            &mut rcu,
        );
        let (tx, rx) = serial.split();
        Board {
            tx,
            rx,
            rx_buffer: [0; 256],
        }
    }

    fn rx_line(&mut self) -> usize {
        for j in 0..self.rx_buffer.len() {
            let c = loop {
                let c = block!(self.rx.read()).unwrap();
                if c != 0xa {
                    // not LF
                    break c;
                }
            };
            if c == 0xd {
                // CR
                return j;
            }
            self.rx_buffer[j] = c;
        }
        self.rx_buffer.len()
    }
}

struct OsnmaInterface {
    osnma: Osnma<SmallStorage>,
    board: Board,
}

impl OsnmaInterface {
    fn new(board: Board) -> OsnmaInterface {
        let pubkey = VerifyingKey::from_sec1_bytes(&OSNMA_PUBKEY).unwrap();
        let osnma = Osnma::<SmallStorage>::from_pubkey(pubkey, false);
        OsnmaInterface { osnma, board }
    }

    fn process_line(&mut self, len: usize) {
        let mut words = core::str::from_utf8(&self.board.rx_buffer[..len])
            .unwrap()
            .split_whitespace();
        let svn = Svn::try_from(words.next().unwrap().parse::<usize>().unwrap()).unwrap();
        let wn = words.next().unwrap().parse::<u16>().unwrap();
        let tow = words.next().unwrap().parse::<u32>().unwrap();
        let gst = Gst::new(wn, tow);
        let data = words.next().unwrap();
        write!(&mut self.board.tx, "{} WN {} TOW {} ", svn, wn, tow).unwrap();
        const OSNMA_BYTES: usize = HKROOT_SECTION_BYTES + MACK_SECTION_BYTES;
        if data.len() == INAV_WORD_BYTES * 2 {
            let mut inav = [0; INAV_WORD_BYTES];
            hex::decode_to_slice(data, &mut inav).unwrap();
            write!(&mut self.board.tx, "INAV\r\n").unwrap();
            self.osnma.feed_inav(&inav, svn, gst);
        } else if data.len() == OSNMA_BYTES * 2 {
            let mut osnma = [0; OSNMA_BYTES];
            hex::decode_to_slice(data, &mut osnma).unwrap();
            write!(&mut self.board.tx, "OSNMA\r\n").unwrap();
            self.osnma.feed_osnma(&osnma, svn, gst);
        }
    }

    fn print_auth_status(&mut self) {
        write!(&mut self.board.tx, "AUTH ADKD=4 ").unwrap();
        match self.osnma.get_timing_parameters() {
            Some(data) => write!(&mut self.board.tx, "TOW {}\r\n", data.gst().tow()).unwrap(),
            None => write!(&mut self.board.tx, "NONE\r\n").unwrap(),
        }
        write!(&mut self.board.tx, "AUTH ADKD=0").unwrap();
        let mut some_adkd0 = false;
        for svn in Svn::iter() {
            if let Some(data) = self.osnma.get_ced_and_status(svn) {
                some_adkd0 = true;
                write!(&mut self.board.tx, " {} TOW {}", svn, data.gst().tow()).unwrap();
            }
        }
        write!(
            &mut self.board.tx,
            "{}\r\n",
            if some_adkd0 { "" } else { " NONE" }
        )
        .unwrap();
    }

    fn ready(&mut self) {
        self.board.tx.write_str("READY\r\n").unwrap();
    }

    fn spin(&mut self) {
        self.ready();
        let len = self.board.rx_line();
        self.process_line(len);
        self.print_auth_status();
    }
}

#[entry]
fn main() -> ! {
    let board = Board::take();
    let mut interface = OsnmaInterface::new(board);

    loop {
        interface.spin();
    }
}
