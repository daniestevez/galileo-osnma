use galileo_osnma::{
    galmon::{navmon::nav_mon_message::GalileoInav, transport::ReadTransport},
    storage::FullStorage,
    types::{BitSlice, NUM_SVNS},
    Gst, Osnma, Svn, Wn,
};
use p256::ecdsa::VerifyingKey;
use spki::DecodePublicKey;
use std::io::Read;

fn load_pubkey(path: &str) -> std::io::Result<VerifyingKey> {
    let mut file = std::fs::File::open(path)?;
    let mut pem = String::new();
    file.read_to_string(&mut pem)?;
    Ok(VerifyingKey::from_public_key_pem(&pem).expect("invalid pubkey"))
}

fn main() -> std::io::Result<()> {
    env_logger::init();

    let args: Vec<_> = std::env::args().collect();

    let pubkey = load_pubkey(&args[1])?;

    let mut read = ReadTransport::new(std::io::stdin());
    let mut osnma = Osnma::<FullStorage>::from_pubkey(pubkey, false);
    let mut timing_parameters_gst: Option<Gst> = None;
    let mut ced_and_status_data: [Option<[u8; 69]>; NUM_SVNS] = [None; NUM_SVNS];

    loop {
        let packet = read.read_packet()?;
        if let Some(
            inav @ GalileoInav {
                contents: inav_word,
                reserved1: osnma_data,
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
            let svn = Svn::try_from(inav.gnss_sv).unwrap();

            osnma.feed_inav(inav_word[..].try_into().unwrap(), svn, gst);
            if let Some(osnma_data) = osnma_data {
                osnma.feed_osnma(osnma_data[..].try_into().unwrap(), svn, gst);
            }

            for svn in Svn::iter() {
                let idx = usize::from(svn) - 1;
                if let Some(data) = osnma.get_ced_and_status(svn) {
                    let mut data_bytes = [0u8; 69];
                    let a = BitSlice::from_slice_mut(&mut data_bytes);
                    let b = data.data();
                    a[..b.len()].copy_from_bitslice(b);
                    if !ced_and_status_data[idx]
                        .map(|d| d == data_bytes)
                        .unwrap_or(false)
                    {
                        log::info!(
                            "new CED and status for E{:02} authenticated \
                                    (authbits = {}, GST = {:?})",
                            svn,
                            data.authbits(),
                            data.gst()
                        );
                        ced_and_status_data[idx] = Some(data_bytes);
                    }
                }
            }

            if let Some(data) = osnma.get_timing_parameters() {
                if !timing_parameters_gst
                    .map(|g| g == data.gst())
                    .unwrap_or(false)
                {
                    log::info!(
                        "new timing parameters authenticated (authbits = {}, GST = {:?})",
                        data.authbits(),
                        data.gst()
                    );
                    timing_parameters_gst = Some(data.gst());
                }
            }
        }
    }
}
