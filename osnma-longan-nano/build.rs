use p256::ecdsa::VerifyingKey;
use spki::DecodePublicKey;
use std::path::{Path, PathBuf};
use std::{env, fs};

fn read_pubkey(path: &str) -> std::io::Result<Vec<u8>> {
    let pem = fs::read_to_string(path)?;
    let key = VerifyingKey::from_public_key_pem(&pem).expect("invalid pubkey");
    let key_point = key.to_encoded_point(true);
    let key_bytes = key_point.as_bytes();
    Ok(Vec::from(key_bytes))
}

fn pubkey_to_rust(pubkey: &[u8], path: &Path) -> std::io::Result<()> {
    fs::write(
        path,
        format!(
            "const OSNMA_PUBKEY: [u8; {}] = {:?};\n",
            pubkey.len(),
            pubkey
        ),
    )
}

fn main() {
    // Put the memory definition somewhere the linker can find it
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    println!("cargo:rustc-link-search={}", out_dir.display());
    fs::copy("memory-cb.x", out_dir.join("memory-cb.x")).unwrap();
    println!("cargo:rerun-if-changed=memory-cb.x");

    let pubkey = read_pubkey("pubkey.pem").unwrap();
    pubkey_to_rust(&pubkey, &out_dir.join("osnma_pubkey.rs")).unwrap();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=pubkey.pem");
}
