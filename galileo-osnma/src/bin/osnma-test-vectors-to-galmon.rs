use anyhow::Result;
use bitvec::{field::BitField, vec::BitVec};
use chrono::NaiveDateTime;
use clap::Parser;
use galileo_osnma::{
    Gst,
    galmon::{
        navmon::{
            NavMonMessage,
            nav_mon_message::{GalileoInav, Type},
        },
        transport::WriteTransport,
    },
    types::BitSlice,
};
use std::{fs, path::PathBuf};

/// Convert OSNMA test vectors to Galmon protobuf format and write to stdout
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input CSV file
    input_file: PathBuf,
}

fn filename_to_gst(filename: &str) -> Result<Gst> {
    let dt = NaiveDateTime::parse_from_str(filename, "%d_%b_%Y_GST_%H_%M_%S.csv")?;
    let t = dt.and_utc().timestamp();
    let gst_epoch_t = 935280000; // 1999-08-22 00:00:00 GST
    let gst_seconds = t - gst_epoch_t;
    const SECS_IN_WEEK: i64 = 24 * 3600 * 7;
    let wn = gst_seconds / SECS_IN_WEEK;
    let tow = gst_seconds - wn * SECS_IN_WEEK;
    Ok(Gst::new(wn.try_into().unwrap(), tow.try_into().unwrap()))
}

fn csv_line_to_pages(line: &str, start_gst: Gst) -> Result<Vec<NavMonMessage>> {
    let mut gst = start_gst;
    let mut fields = line.split(',');
    let wrong_format = || anyhow::anyhow!("CSV has wrong format");
    let svn: u32 = fields.next().ok_or_else(wrong_format)?.parse()?;
    // skip length CSV field
    fields.next().ok_or_else(wrong_format)?;
    let data = hex::decode(fields.next().ok_or_else(wrong_format)?)?;
    const PAGE_SIZE: usize = 240 / 8;
    if data.len() % PAGE_SIZE != 0 {
        return Err(wrong_format());
    }
    let messages = data
        .chunks_exact(PAGE_SIZE)
        .map(|page| {
            let gnss_wn: u32 = gst.wn().into();
            let gnss_tow = gst.tow();
            gst = gst.add_seconds(2);
            let gnss_id = 2;
            let gnss_sv = svn;
            let page = BitSlice::from_slice(page);
            let mut inav_data = BitVec::from_bitslice(&page[2..2 + 112]);
            inav_data.extend_from_bitslice(&page[122..122 + 16]);
            inav_data.force_align();
            inav_data.set_uninitialized(false);
            let contents = inav_data.into_vec();
            let sigid = Some(1);
            let mut reserved1 = BitVec::from_bitslice(&page[120 + 2 + 16..120 + 2 + 16 + 40]);
            reserved1.force_align();
            let reserved1 = Some(reserved1.into_vec());
            let mut reserved2 = BitVec::from_bitslice(&page[240 - 8 - 6..240 - 6]);
            reserved2.force_align();
            let reserved2 = reserved2.into_vec();
            let ssp = Some(u32::from(reserved2[0]));
            let reserved2 = Some(reserved2);
            // Galmon gets 24 bits instead of 22 for SAR
            let mut sar = BitVec::from_bitslice(&page[120 + 2 + 16 + 40..120 + 2 + 16 + 40 + 24]);
            sar.force_align();
            let sar = Some(sar.into_vec());
            // This is only 2 bits as the LSBs of an u8
            let spare = page[120 + 2 + 16 + 40 + 22..120 + 2 + 16 + 40 + 22 + 2].load_be::<u8>();
            let spare = Some(vec![spare]);
            let mut crc = BitVec::from_bitslice(&page[240 - 8 - 6 - 24..240 - 8 - 6]);
            crc.force_align();
            let crc = Some(crc.into_vec());
            let gi = Some(GalileoInav {
                gnss_wn,
                gnss_tow,
                gnss_id,
                gnss_sv,
                contents,
                sigid,
                reserved1,
                reserved2,
                sar,
                spare,
                crc,
                ssp,
            });
            let type_ = Type::GalileoInavType.into();
            let source_id = 0;
            let local_utc_seconds = 0;
            let local_utc_nanoseconds = 0;
            NavMonMessage {
                source_id,
                r#type: type_,
                local_utc_seconds,
                local_utc_nanoseconds,
                gi,
                ..Default::default()
            }
        })
        .collect();
    Ok(messages)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let filename = args
        .input_file
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("input path does not contain a filename"))?
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("input filename does not contain valid UTF-8"))?;

    let start_gst = filename_to_gst(filename)?;

    let csv = fs::read_to_string(args.input_file)?;
    let mut csv = csv.lines();
    // discard csv header
    csv.next()
        .ok_or_else(|| anyhow::anyhow!("input file is empty"))?;
    let mut pages = Vec::new();
    for line in csv {
        pages.push(csv_line_to_pages(line, start_gst)?);
    }

    let mut write_transport = WriteTransport::new(std::io::stdout());

    let mut page_num = 0;
    let mut has_pages = true;
    while has_pages {
        has_pages = false;
        for svn_pages in &pages {
            if let Some(page) = svn_pages.get(page_num) {
                has_pages = true;
                write_transport.write_packet(page)?;
            }
        }
        page_num += 1;
    }

    Ok(())
}
