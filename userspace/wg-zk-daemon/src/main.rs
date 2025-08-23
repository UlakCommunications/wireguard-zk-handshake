mod netlink;

use crate::netlink::WGZK_GENL;
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use ed25519_dalek::SigningKey;
use sha2::Digest;

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, edwards::EdwardsPoint, scalar::Scalar};
use sha2::Sha512;
use std::time::Duration;

// MUST match the prover side
const DOMAIN: &[u8] = b"WGZK-POK-v1";
const MSG: &[u8] = b"WGZK-POK-v1|demo";

use curve25519_dalek::edwards::CompressedEdwardsY;
// use rand::RngCore;
use tokio::{fs as tfs, time::sleep};

/// WireGuard ZK userspace CLI
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send VERIFY_ACK (cmd=1) with peer_index (u32) and result (u8)
    SendVerifyAck {
        /// peer index (u32)
        #[arg(long)]
        peer_index: u32,
        /// result (u8), e.g. 0/1
        #[arg(long)]
        result: u8,
        /// family name (defaults to wgzk)
        #[arg(long, default_value = WGZK_GENL)]
        family: String,
        /// generic netlink version (defaults to 1)
        #[arg(long, default_value_t = 1u8)]
        version: u8,
    },
    /// Run the daemon that watches zk_handshake and sends ACKs
    Daemon,
    /// Prover: generate (R,S) and send WGZK_CMD_SET_PROOF over netlink
    SendProof {
        /// peer internal id (u64)
        #[arg(long)]
        peer_id: u64,
        /// ed25519 secret key (32-byte hex)
        #[arg(long)]
        sk_hex: String,
        /// family name (defaults to wgzk)
        #[arg(long, default_value = "wgzk")]
        family: String,
        /// genl version (defaults to 1)
        #[arg(long, default_value_t = 1u8)]
        version: u8,
    },
}

// --- crypto helpers ---

fn decompress_point(bytes: &[u8]) -> Option<EdwardsPoint> {
    CompressedEdwardsY::from_slice(bytes).ok()?.decompress()
}

/// Compute Schnorr PoK over Ed25519 group and send via netlink
async fn compute_and_send_proof(
    peer_id: u64,
    sk_hex: &str,
    family: &str,
    version: u8,
) {
    // load signing key
    let sk_bytes = hex::decode(sk_hex).context("sk hex decode").unwrap();
    let sk_arr: [u8; 32] = sk_bytes.try_into().map_err(|_| anyhow::anyhow!("sk must be 32 bytes")).unwrap();
    let sk = SigningKey::from_bytes(&sk_arr);

    // secret scalar x, public key A
    let x = ed25519_secret_scalar(&sk);
    let _a = (x * G).compress(); // VerifyingKey in dalek derives from ed25519 math, but we need point on curve25519-dalek side

    // nonce k and R
    let mut buf = [0u8; 64];
    use getrandom;
    use curve25519_dalek::scalar::Scalar;

    getrandom::fill(&mut buf).expect("TODO: panic message");                           // OS RNG
    let k = Scalar::from_bytes_mod_order_wide(&buf);

    let _r = (k * G).compress();

    // c = H(DOMAIN || A || R || MSG)  <-- MUST match the verifier/kernel
    let mut h = Sha512::new();
    h.update(DOMAIN);
    h.update(_a.as_bytes());
    h.update(_r.as_bytes());
    h.update(MSG);
    let c = Scalar::from_hash(h);

    // s = k + c·x
    let s = k + c * x;

    let r_bytes = _r.to_bytes();
    let s_bytes = s.to_bytes();

    // push to kernel
    netlink::send_set_proof(family, version, peer_id, &r_bytes, &s_bytes).await
}

fn verify_proof(pk: EdwardsPoint, zk_r: EdwardsPoint, zk_s: Scalar) -> bool {
    // c = H(domain || A || R || msg)  ← same as your prover
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN);
    hasher.update(pk.compress().as_bytes());
    hasher.update(zk_r.compress().as_bytes());
    hasher.update(MSG);
    let c = Scalar::from_hash(hasher);

    // s·G == R + c·A
    zk_s * G == zk_r + c * pk
}

pub fn load_static_pk() -> Result<EdwardsPoint> {
    let s = std::fs::read_to_string("config/static_pk.hex")
        .with_context(|| "reading static_pk.hex failed")?;
    let s = s.trim();
    if s.is_empty() {
        bail!("static_pk.hex is empty");
    }
    let bytes = hex::decode(s).with_context(|| "static_pk.hex is not valid hex")?;
    if bytes.len() != 32 {
        bail!("static_pk.hex must be 32 bytes (64 hex chars), got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    CompressedEdwardsY(arr)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("invalid point in static_pk.hex"))
}


// --- daemon ---

async fn run_daemon(pk: EdwardsPoint) -> Result<()> {
    const HANDSHAKE_PATH: &str = "/sys/kernel/debug/wireguard/zk_handshake";
    let mut last96 = [0u8; 96];

    loop {
        match tfs::read(HANDSHAKE_PATH).await {
            Ok(buf) if buf.len() >= 96 && &buf[..96] != &last96 => {
                eprintln!("New handshake received");
                last96.copy_from_slice(&buf[..96]);

                // offsets based on your format
                // [0..4]=? (ignored), [4..8]=sender_index (LE), [32..64]=R, [64..96]=s
                let sender_index = match buf[4..8].try_into() {
                    Ok(v) => u32::from_le_bytes(v),
                    Err(_) => {
                        eprintln!("Bad sender_index slice; skipping");
                        sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                };

                let zk_r = match decompress_point(&buf[32..64]) {
                    Some(p) => p,
                    None => {
                        eprintln!("Malformed zk_r for peer {}", sender_index);
                        // send failure ack but don’t crash
                        if let Err(e) = netlink::send_verify_ack(WGZK_GENL, 1, sender_index, 0).await {
                            eprintln!("netlink ack (fail) error: {e:#}");
                        }
                        sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                };

                let Ok(s_bytes) = <[u8; 32]>::try_from(&buf[64..96]) else {
                    eprintln!("Bad zk_s slice for peer {sender_index}");
                    if let Err(e) = netlink::send_verify_ack(WGZK_GENL, 1, sender_index, 0).await {
                        eprintln!("netlink ack (fail) error: {e:#}");
                    }
                    sleep(Duration::from_millis(200)).await;
                    continue;
                };

                let Some(zk_s) = Scalar::from_canonical_bytes(s_bytes).into() else {
                    eprintln!("Non-canonical zk_s for peer {sender_index}");
                    if let Err(e) = netlink::send_verify_ack(WGZK_GENL, 1, sender_index, 0).await {
                        eprintln!("netlink ack (fail) error: {e:#}");
                    }
                    sleep(Duration::from_millis(200)).await;
                    continue;
                };

                let ok = verify_proof(pk, zk_r, zk_s);
                if ok {
                    eprintln!("ZK verified for peer {}", sender_index);
                    if let Err(e) = netlink::send_verify_ack(WGZK_GENL, 1, sender_index, 1).await {
                        eprintln!("netlink ack (success) error: {e:#}");
                    }
                } else {
                    eprintln!("ZK failed for peer {}", sender_index);
                    if let Err(e) = netlink::send_verify_ack(WGZK_GENL, 1, sender_index, 0).await {
                        eprintln!("netlink ack (fail) error: {e:#}");
                    }
                }
            }
            Ok(_) => { /* no change or too short; ignore */ }
            Err(e) => {
                // debugfs may momentarily be missing; don’t crash the daemon
                eprintln!("read {} failed: {e}", HANDSHAKE_PATH);
            }
        }

        // simple, reliable backoff (you can switch to inotify later)
        sleep(Duration::from_millis(200)).await;
    }
}

/// Ed25519 gizli skaler (x) üret: SHA-512(seed), ilk 32 baytı clamp et, sonra Scalar’a çevir.
/// Not: curve25519-dalek 4.x’te `Scalar::from_bits` YOK; `from_bytes_mod_order` kullan.
fn ed25519_secret_scalar(sk: &SigningKey) -> Scalar {
    // Ed25519: SHA-512(seed) -> a (32 byte) clamp
    let mut h = Sha512::new();
    h.update(sk.to_bytes());
    let digest = h.finalize(); // 64 byte

    let mut a = [0u8; 32];
    a.copy_from_slice(&digest[..32]);

    // clamp
    a[0]  &= 248;
    a[31] &= 63;
    a[31] |= 64;

    // from_bits kaldırıldı → from_bytes_mod_order
    Scalar::from_bytes_mod_order(a)
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting wg-zk-daemon...");
    let pk = load_static_pk().with_context(|| "loading static public key")?;
    let cli = Cli::parse();


        match cli.cmd {
            Commands::SendVerifyAck { peer_index, result, family, version } => {
            // if your netlink module exposes an async helper that resolves family+builds msg:
            netlink::send_verify_ack(&family, version, peer_index, result)
                .await
                .with_context(|| "sending VERIFY_ACK failed")?;
            Ok(())
        },
        Commands::Daemon => run_daemon(pk).await,
            Commands::SendProof { peer_id, sk_hex, family, version } => {
                compute_and_send_proof(peer_id, &sk_hex, &family, version).await;
                    // .context("SET_PROOF failed").unwrap();
                eprintln!("SET_PROOF sent for peer_id={peer_id}");
                Ok(())
            }

    }

}