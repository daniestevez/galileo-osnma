#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::bitfields::{DsmHeader, DsmKroot, Mack, NmaHeader};
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::dsm::CollectDsm;
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::galmon::navmon::nav_mon_message::GalileoInav;
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::galmon::transport::ReadTransport;
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::subframe::CollectSubframe;
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::tesla::Key;

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
    let mut sizes = None;
    let mut chain_params = None;
    let mut current_tesla_key: Option<Key> = None;
    loop {
        let packet = read.read_packet()?;
        if let Some(
            inav @ GalileoInav {
                reserved1: Some(osnma),
                ..
            },
        ) = &packet.gi
        {
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
                let nma_header = &hkroot[..1].try_into().unwrap();
                let nma_header = NmaHeader(nma_header);
                let dsm_header = &hkroot[1..2].try_into().unwrap();
                let dsm_header = DsmHeader(dsm_header);
                let dsm_block = &hkroot[2..].try_into().unwrap();
                if let Some(dsm) = dsm.feed(dsm_header, dsm_block) {
                    let dsm_kroot = DsmKroot(dsm);
                    sizes = Some((dsm_kroot.key_size().unwrap(), dsm_kroot.tag_size().unwrap()));
                    chain_params = Some(dsm_kroot.chain_parameters());
                    log::info!("chain_params = {:?}", chain_params);
                    if !dsm_kroot.check_padding(nma_header) {
                        log::error!("wrong DSM-KROOT padding");
                    } else {
                        log::info!("correct DSM-KROOT padding");
                    }
                    if !dsm_kroot.check_signature(nma_header, &pubkey) {
                        log::error!("wrong DSM-KROOT ECDSA signature");
                    } else {
                        log::info!("correct DSM-KROOT ECDSA signature");
                    }
                }
                if let Some((key_size, tag_size)) = sizes {
                    let mack = Mack::new(mack, key_size, tag_size);
                    let key = Key::from_bitslice(mack.key(), gst);
                    log::info!("TESLA key = {:?}", key);
                    if let Some(k) = current_tesla_key {
                        if k.gst_subframe() == key.gst_subframe() && k != key {
                            log::error!(
                                "got two different TESLA keys with same GST: {:?} and {:?}",
                                k,
                                key
                            );
                        } else if k.gst_subframe() != key.gst_subframe() {
                            let owf = key.one_way_function(&chain_params.unwrap());
                            log::info!("got TESLA key for new GST: {:?}", key);
                            log::info!("its OWF is {:?}", owf);
                            log::info!("the previous TESLA key is {:?}", k);
                            if k.gst_subframe() == owf.gst_subframe() {
                                if k != owf {
                                    log::error!("OWF != previous key");
                                } else {
                                    log::info!("OWF == previous key");
                                }
                            } else {
                                log::warn!(
                                    "OWF and previous key GSTs differ; we have skipped some keys"
                                );
                            }
                            current_tesla_key = Some(key);
                        }
                    } else {
                        current_tesla_key = Some(key);
                    }
                }
            }
        }
    }
}

#[cfg(not(all(feature = "galmon", feature = "pem")))]
fn main() {}
