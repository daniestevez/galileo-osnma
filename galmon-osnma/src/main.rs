use galileo_osnma::{
    galmon::{navmon::nav_mon_message::GalileoInav, transport::ReadTransport},
    storage::FullStorage,
    types::{BitSlice, NUM_SVNS},
    Gst, InavBand, Osnma, Svn, Wn,
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
    let mut timing_parameters: [Option<[u8; 18]>; NUM_SVNS] = [None; NUM_SVNS];
    let mut ced_and_status_data: [Option<[u8; 69]>; NUM_SVNS] = [None; NUM_SVNS];

    loop {
        let packet = read.read_packet()?;
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
            let svn = Svn::try_from(inav.gnss_sv).unwrap();
            let band = match sigid {
                1 => InavBand::E1B,
                5 => InavBand::E5B,
                _ => {
                    log::error!("INAV word received on non-INAV band: sigid = {}", sigid);
                    continue;
                }
            };

            osnma.feed_inav(inav_word[..].try_into().unwrap(), svn, gst, band);
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
                            "new CED and status for {} authenticated \
                                    (authbits = {}, GST = {:?})",
                            svn,
                            data.authbits(),
                            data.gst()
                        );
                        ced_and_status_data[idx] = Some(data_bytes);
                    }
                }
                if let Some(data) = osnma.get_timing_parameters(svn) {
                    let mut data_bytes = [0u8; 18];
                    let a = BitSlice::from_slice_mut(&mut data_bytes);
                    let b = data.data();
                    a[..b.len()].copy_from_bitslice(b);
                    if !timing_parameters[idx]
                        .map(|d| d == data_bytes)
                        .unwrap_or(false)
                    {
                        log::info!(
                            "new timing parameters for {} authenticated (authbits = {}, GST = {:?})",
			    svn,
                            data.authbits(),
                            data.gst()
			);
                        timing_parameters[idx] = Some(data_bytes);
                    }
                }
            }
        }
    }
}
