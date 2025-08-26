use anyhow::Result;
use std::path::Path;
use tokio::{fs::File, io::AsyncReadExt, time::{sleep, Duration}};
use std::collections::HashSet;
use tokio::sync::{Mutex, OnceCell};

mod netlink;
mod zk;
use dotenvy::dotenv;

use curve25519_dalek::scalar::Scalar;
use netlink::*;
use zk::{parse_pk_hex, parse_sk_hex};

static SK: OnceCell<Scalar> = OnceCell::const_new();
static PK: OnceCell<[u8; 32]> = OnceCell::const_new();
/// Aynı peer_id için birden fazla eşzamanlı üretimi engelle.
static IN_FLIGHT: OnceCell<Mutex<HashSet<u64>>> = OnceCell::const_new();


async fn inflight() -> &'static Mutex<HashSet<u64>> {
    IN_FLIGHT.get_or_init(|| async { Mutex::new(HashSet::new()) }).await
}

async fn load_keys() -> Result<()> {
    if let Ok(sk_hex) = std::env::var("WGZK_SK_HEX") {
        SK.get_or_try_init(|| async move {
            // DİKKAT: sadece parse_*’ı döndür, Ok(...) yapma
            parse_sk_hex(&sk_hex)
        }).await?;
    }
    if let Ok(pk_hex) = std::env::var("WGZK_PK_HEX") {
        PK.get_or_try_init(|| async move {
            parse_pk_hex(&pk_hex)
        }).await?;
    }
    Ok(())
}
#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {

    eprintln!( "[daemon] Starting" );
    // Load variables from .env file (if present)
    dotenv().ok();
    eprintln!( "[daemon] Env loaded" );
    load_keys().await?;
    eprintln!( "[daemon] Keys loaded" );

    inflight().await;

    eprintln!( "[daemon] Inflight loaded" );

    // // connect + resolve + join
    // let mut sock = connect_genl().await?;
    // let resolved = resolve_family_and_groups(&mut sock, "wgzk").await?;
    // let events_gid = *resolved.mcast_groups.get("events")
    //     .ok_or_else(|| anyhow::anyhow!("wgzk: 'events' multicast group missing"))?;
    // add_mcast(&sock, events_gid).await?;
    // // let family_id = resolved.family_id;

    // CLIENT TASK (NEED_PROOF → SET_PROOF)
    let client_task = tokio::spawn(async move {

        eprintln!( "[daemon] Connecting to genl" );

        let mut sock = connect_genl().await.expect("genl connect (client)");

        eprintln!( "[daemon] Connecting to wgzk" );
        let resolved = resolve_family_and_groups(&mut sock, "wgzk").await.expect("resolve wgzk");
        eprintln!("[wgzk] family_id={}, events_mc_id={}", resolved.family_id, resolved.mcast_groups.get("events").unwrap());

        eprintln!( "[daemon] Connecting to mcast" );
        add_mcast(&sock, *resolved.mcast_groups.get("events").unwrap()).await.expect("join events");
        eprintln!("[wgzk] joined events");
        eprintln!("[wgzk] ns={}", std::fs::read_link("/proc/self/ns/net").unwrap().display());
        eprintln!("[wgzk] family_id={}, events_mc_id={}", resolved.family_id, resolved.mcast_groups.get("events").unwrap());
        let family_id = resolved.family_id;

        eprintln!( "[daemon] Connecting to family_id" );
        loop {

            match recv_next(&mut sock).await {
                Ok((_nl_type, genl)) => {

                    eprintln!( "[daemon] Recv OK" );
                    if *genl.cmd() == WgzkCmd::NeedProof as u8 {
                        if let Some(ev) = try_parse_need_proof(&genl) {
                            // Use per‑initiation token for dedup (best against races)
                            let token = ev.token.unwrap_or(0) as u64;
                            let mut inflight1 = inflight().await.lock().await;
                            if !inflight1.insert(token) {
                                continue; // already in-flight
                            }
                            drop(inflight1);

                            eprintln!(
                                "[daemon] NEED_PROOF ifindex={} peer_id={} token={:?}",
                                ev.ifindex, ev.peer_id, ev.token
                            );

                            let sk = SK.get().expect("WGZK_SK_HEX missing");
                            let (r, s) = zk::prove(sk, b"");

                            if let Err(e) = send_set_proof(&mut sock, family_id, ev.peer_id, ev.token, &r, &s,ev.ifindex).await {
                                eprintln!("[daemon] send_set_proof error: {e:?}");
                            } else {
                                eprintln!(
                                    "[daemon] SET_PROOF sent peer_id={} token={:?}",
                                    ev.peer_id, ev.token
                                );
                            }

                            inflight().await.lock().await.remove(&token);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[daemon] recv error: {e:?}");
                    sleep(Duration::from_millis(250)).await;
                }
            }
        }
    });

    // SERVER TASK (debugfs → VERIFY)
    let server_task = tokio::spawn(async move {
        let mut sock = connect_genl().await.expect("genl connect (server)");
        let resolved = resolve_family_and_groups(&mut sock, "wgzk").await.expect("resolve wgzk");
        let family_id = resolved.family_id;

        let hand_path = Path::new("/sys/kernel/debug/wireguard/zk_handshake");
        let pend_path = Path::new("/sys/kernel/debug/wireguard/zk_pending");

        loop {
            let mut pending = String::new();
            if let Ok(mut f) = File::open(pend_path).await { let _ = f.read_to_string(&mut pending).await; }
            let sender_index = pending
                .lines()
                .skip_while(|l| !l.starts_with("Index"))
                .nth(1)
                .and_then(|line| line.split_whitespace().next())
                .and_then(|s| s.parse::<u32>().ok());

            if let Some(idx) = sender_index {
                let mut raw = vec![0u8; 96];
                if let Ok(mut f) = File::open(hand_path).await {
                    let _ = f.read_exact(&mut raw).await;
                }
                let pk = PK.get().expect("WGZK_PK_HEX missing");
                let mut r = [0u8; 32];
                let mut s = [0u8; 32];
                if raw.len() >= 96 {
                    r.copy_from_slice(&raw[32..64]);
                    s.copy_from_slice(&raw[64..96]);
                }

                let ok = zk::verify(pk, &r, &s, b"");
                if let Err(e) = send_verify(&mut sock, family_id, idx, if ok { 1 } else { 0 }).await {
                    eprintln!("[server] VERIFY send error: {e:?}");
                } else {
                    eprintln!("[server] VERIFY idx={} result={}", idx, ok);
                }

                sleep(Duration::from_millis(200)).await;
            }
        }
    });
    tokio::select! {
        _ = client_task => {},
        _ = server_task => {},
        _ = tokio::signal::ctrl_c() => {
            eprintln!("shutdown");
        }
    }

    Ok(())
}