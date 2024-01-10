use clap::Parser;
use galileo_osnma::{
    galmon::{navmon::nav_mon_message::GalileoInav, transport::ReadTransport},
    storage::FullStorage,
    types::{BitSlice, NUM_SVNS},
    Gst, InavBand, Osnma, PublicKey, Svn, Validated, Wn,
};
use p256::ecdsa::VerifyingKey;
use spki::DecodePublicKey;
use std::io::Read;

/// Process OSNMA data reading Galmon protobuf from stdin
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Merkle tree root in hex.
    #[arg(long)]
    merkle_root: Option<String>,
    /// Path to the public key in PEM format.
    #[arg(long)]
    pubkey: Option<String>,
    /// Only process slow MAC data.
    #[arg(long)]
    slow_mac_only: bool,
}

fn load_pubkey(path: &str) -> std::io::Result<PublicKey<Validated>> {
    let mut file = std::fs::File::open(path)?;
    let mut pem = String::new();
    file.read_to_string(&mut pem)?;
    let pubkey = VerifyingKey::from_public_key_pem(&pem).expect("invalid pubkey");
    Ok(PublicKey::from_p256(pubkey).force_valid())
}

fn main() -> std::io::Result<()> {
    env_logger::init();
    let args = Args::parse();

    if args.merkle_root.is_none() && args.pubkey.is_none() {
        log::error!("at least either the Merkle tree root or the public key must be specified");
        // TODO: return an error exit code
        return Ok(());
    }

    let pubkey = if let Some(pubkey_path) = &args.pubkey {
        Some(load_pubkey(pubkey_path)?)
    } else {
        None
    };

    let mut osnma: Osnma<FullStorage> = if let Some(merkle) = &args.merkle_root {
        let merkle = hex::decode(merkle)
            .expect("invalid Merkle tree hex data")
            .try_into()
            .expect("wrong length of Merkle tree hex data");
        Osnma::from_merkle_tree(merkle, pubkey, args.slow_mac_only)
    } else {
        // Here pubkey shouldn't be None, because Merkle tree is None and we
        // have checked that at least one of both is not None.
        Osnma::from_pubkey(pubkey.unwrap(), args.slow_mac_only)
    };

    let mut read = ReadTransport::new(std::io::stdin());
    let mut timing_parameters: [Option<[u8; 18]>; NUM_SVNS] = [None; NUM_SVNS];
    let mut ced_and_status_data: [Option<[u8; 69]>; NUM_SVNS] = [None; NUM_SVNS];
    let mut current_subframe = None;
    let mut last_tow_mod_30 = 0;

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
            let mut tow = inav.gnss_tow % secs_in_week;
            let wn = Wn::try_from(inav.gnss_wn).unwrap()
                + Wn::try_from(inav.gnss_tow / secs_in_week).unwrap();

            // Fix bug in Galmon data:
            //
            // Often, the E1B word 16 starting at TOW = 29 mod 30 will have the
            // TOW of the previous word 16 in the subframe, which starts at TOW
            // = 15 mod 30. We detect this condition by looking at the last tow
            // mod 30 that we saw and fixing if needed.
            if tow % 30 == 15 && last_tow_mod_30 >= 19 {
                log::debug!(
                    "fixing wrong TOW for SVN {}; tow = {}, last tow mod 30 = {}",
                    inav.gnss_sv,
                    tow,
                    last_tow_mod_30
                );
                tow += 29 - 15; // wn rollover is not possible by this addition
            }
            last_tow_mod_30 = tow % 30;

            let gst = Gst::new(wn, tow);
            if let Some(current) = current_subframe {
                if current > gst.gst_subframe() {
                    // Avoid processing INAV words that are in a previous subframe
                    log::warn!(
                        "dropping INAV word from previous subframe (current subframe {:?}, \
			 this INAV word {:?} SVN {} band {})",
                        current,
                        gst,
                        inav.gnss_sv,
                        sigid
                    );
                    continue;
                }
            }
            current_subframe = Some(gst.gst_subframe());
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
