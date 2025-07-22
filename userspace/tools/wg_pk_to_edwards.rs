use curve25519_dalek::montgomery::MontgomeryPoint;
use hex;

fn main() {
    let wg_hex = std::env::args().nth(1).expect("hex pubkey needed");
    let raw = hex::decode(&wg_hex).expect("invalid hex");
    let m = MontgomeryPoint::from_slice(&raw);
    if let Some(ed) = m.to_edwards(0) {
        println!("{}", hex::encode(ed.compress().as_bytes()));
    } else {
        eprintln!("❌ conversion failed");
    }
}
