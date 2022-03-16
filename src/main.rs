#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::bitfields::{DsmHeader, DsmKroot, Mack, NmaHeader};
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::dsm::CollectDsm;
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::galmon::navmon::nav_mon_message::GalileoInav;
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::galmon::transport::ReadTransport;
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::gst::Gst;
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::mack::MackStorage;
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::navmessage::CollectNavMessage;
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::subframe::CollectSubframe;
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::tesla::Key;
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::types::Validated;

#[cfg(all(feature = "galmon", feature = "pem"))]
use p256::ecdsa::VerifyingKey;
#[cfg(all(feature = "galmon", feature = "pem"))]
use spki::DecodePublicKey;
#[cfg(all(feature = "galmon", feature = "pem"))]
use std::io::Read;

#[cfg(all(feature = "galmon", feature = "pem"))]
fn load_pubkey(path: &str) -> std::io::Result<VerifyingKey> {
    let mut file = std::fs::File::open(path)?;
    let mut pem = String::new();
    file.read_to_string(&mut pem)?;
    Ok(VerifyingKey::from_public_key_pem(&pem).expect("invalid pubkey"))
}

#[cfg(all(feature = "galmon", feature = "pem"))]
fn main() -> std::io::Result<()> {
    #[cfg(feature = "env_logger")]
    env_logger::init();

    let args: Vec<_> = std::env::args().collect();

    let pubkey = load_pubkey(&args[1])?;

    let mut read = ReadTransport::new(std::io::stdin());
    let mut subframe = CollectSubframe::new();
    let mut dsm = CollectDsm::new();
    let mut tesla: Option<Key<Validated>> = None;
    let mut navmessage = CollectNavMessage::new();
    let mut mack_storage = MackStorage::new();
    loop {
        let packet = read.read_packet()?;
        if let Some(
            inav @ GalileoInav {
                contents: inav_word,
                reserved1: Some(osnma),
                ..
            },
        ) = &packet.gi
        {
            let gst = Gst::new(inav.gnss_wn.try_into().unwrap(), inav.gnss_tow);
            navmessage.feed(
                inav_word[..].try_into().unwrap(),
                inav.gnss_sv.try_into().unwrap(),
                gst,
            );
            if osnma.iter().all(|&x| x == 0) {
                // no OSNMA data in this word
                continue;
            }
            if let Some((hkroot, mack, gst)) = subframe.feed(
                osnma[..].try_into().unwrap(),
                inav.gnss_wn.try_into().unwrap(),
                inav.gnss_tow,
                inav.gnss_sv.try_into().unwrap(),
            ) {
                mack_storage.store(mack, inav.gnss_sv.try_into().unwrap(), gst);
                let nma_header = &hkroot[..1].try_into().unwrap();
                let nma_header = NmaHeader(nma_header);
                let dsm_header = &hkroot[1..2].try_into().unwrap();
                let dsm_header = DsmHeader(dsm_header);
                let dsm_block = &hkroot[2..].try_into().unwrap();
                if let Some(dsm) = dsm.feed(dsm_header, dsm_block) {
                    let dsm_kroot = DsmKroot(dsm);
                    match Key::from_dsm_kroot(nma_header, dsm_kroot, &pubkey) {
                        Ok(key) => {
                            log::info!("verified KROOT");
                            if tesla.is_none() {
                                tesla = Some(key);
                                log::info!("initializing TESLA info to {:?}", tesla);
                            }
                        }
                        Err(e) => log::error!("could not verify KROOT: {:?}", e),
                    }
                }
                if let Some(valid_key) = tesla {
                    let mack = Mack::new(
                        mack,
                        valid_key.chain().key_size_bits(),
                        valid_key.chain().tag_size_bits(),
                    );
                    let key = Key::from_bitslice(mack.key(), gst, valid_key.chain());
                    if key.gst_subframe() > valid_key.gst_subframe() {
                        match valid_key.validate_key(&key) {
                            Ok(new_valid_key) => {
                                log::info!(
                                    "new TESLA key {:?} successfully validated by {:?}",
                                    new_valid_key,
                                    valid_key
                                );
                                tesla = Some(new_valid_key);
                            }
                            Err(e) => log::error!(
                                "got {:?} trying to validate TESLA key {:?} using {:?}",
                                e,
                                key,
                                valid_key
                            ),
                        }
                    }
                    if let Some(navdata) = navmessage
                        .ced_and_status(inav.gnss_sv.try_into().unwrap(), gst.add_seconds(-60))
                    {
                        let previous_gst = gst.add_seconds(-30);
                        if let Some(previous_mack) =
                            mack_storage.get(inav.gnss_sv.try_into().unwrap(), previous_gst)
                        {
                            let previous_mack = Mack::new(
                                previous_mack,
                                valid_key.chain().key_size_bits(),
                                valid_key.chain().tag_size_bits(),
                            );

                            log::info!(
                                "attempting to validate tag0 for E{:02} and {:?}",
                                inav.gnss_sv,
                                previous_gst
                            );
                            if tesla.unwrap().validate_tag0(
                                previous_mack.tag0(),
                                previous_gst,
                                inav.gnss_sv.try_into().unwrap(),
                                navdata,
                            ) {
                                log::info!("tag0 authentication correct");
                            } else {
                                log::error!("tag0 authentication wrong");
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(not(all(feature = "galmon", feature = "pem")))]
fn main() {}
