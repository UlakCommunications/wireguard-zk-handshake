mod netlink;

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, edwards::EdwardsPoint, scalar::Scalar};
use sha2::{Digest, Sha512};
use std::{fs, thread, time::Duration};
fn decompress_point(bytes: &[u8]) -> Option<EdwardsPoint> {
    match curve25519_dalek::edwards::CompressedEdwardsY::from_slice(bytes) {
        Ok(comp) => comp.decompress(),
        Err(_) => None,
    }
} 

fn verify_proof(pk: EdwardsPoint, zk_r: EdwardsPoint, zk_s: Scalar) -> bool {
    let mut hasher = Sha512::new();
    hasher.update(G.compress().as_bytes());
    hasher.update(pk.compress().as_bytes());
    hasher.update(zk_r.compress().as_bytes());
    let c = Scalar::from_hash(hasher);

    zk_s * G == zk_r + c * pk
}

fn load_static_pk() -> EdwardsPoint {
    let hex = fs::read_to_string("config/static_pk.hex").expect("missing static_pk");
    let pk_bytes = hex::decode(hex.trim()).expect("bad hex");
    decompress_point(&pk_bytes).expect("invalid point")
}

fn main() {
    println!("Starting wg-zk-daemon...");
    let mut last = [0u8; 96];
    let pk = load_static_pk();

    loop {
        if let Ok(buf) = fs::read("/sys/kernel/debug/wireguard/zk_handshake") {
            if buf.len() >= 96 && &buf[..96] != &last {
                println!("New handshake received");
                last[..96].copy_from_slice(&buf[..96]);
                let sender_index = u32::from_le_bytes(buf[4..8].try_into().unwrap());

                let zk_r = decompress_point(&buf[32..64]).unwrap();
                let zk_s = Scalar::from_canonical_bytes(buf[64..96].try_into().unwrap()).unwrap();

                if verify_proof(pk, zk_r, zk_s) {
                    println!("ZK verified for peer {}", sender_index);
                    netlink::send_wgzk_ack(sender_index, 1).unwrap();
                } else {
                    println!("ZK failed for peer {}", sender_index);
                    netlink::send_wgzk_ack(sender_index, 0).unwrap();
                }
            }
        }
        thread::sleep(Duration::from_millis(200));
    }
}
