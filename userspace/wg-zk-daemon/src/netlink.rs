use neli::{
    consts::{
        genl::CtrlAttr, // only needed if you parse ctrl replies elsewhere
        nl::{GenlId, NlTypeWrapper, NlmF},
        socket::NlFamily,
    },
    genl::{AttrType, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder},
    nl::NlPayload,
    router::synchronous::NlRouter,
    types::{Buffer, GenlBuffer},
    utils::Groups,
};

const WGZK_GENL: &str = "wgzk_genl";
const WGZK_VERSION: u8 = 1;
const WGZK_CMD_VERIFY: u8 = 1;
const WGZK_ATTR_PEER_INDEX: u16 = 1;
const WGZK_ATTR_RESULT: u16 = 2;

pub fn send_wgzk_ack(peer_index: u32, result: u8) -> Result<(), Box<dyn std::error::Error>> {
    // Use NlRouter in neli 0.7
    let (router, _rx) = NlRouter::connect(NlFamily::Generic, None, Groups::empty())?;

    // Family lookup moved here
    let family_id = router.resolve_genl_family(WGZK_GENL)?;

    // Build attrs as GenlBuffer<u16, Buffer>
    let attrs: GenlBuffer<u16, Buffer> = vec![
        NlattrBuilder::default()
            .nla_type(AttrType::from(WGZK_ATTR_PEER_INDEX))
            .nla_payload(Buffer::from(peer_index.to_ne_bytes().to_vec()))
            .build()?,
        NlattrBuilder::default()
            .nla_type(AttrType::from(WGZK_ATTR_RESULT))
            .nla_payload(Buffer::from([result].to_vec()))
            .build()?,
    ]
        .into_iter()
        .collect();

    // Build genl header
    let genlhdr: Genlmsghdr<u8, u16> = GenlmsghdrBuilder::default()
        .cmd(WGZK_CMD_VERIFY)
        .version(WGZK_VERSION)
        .attrs(attrs)
        .build()?;

    // Send via router; this validates ACKs and seq internally
    let recv = router.send::<_, _, NlTypeWrapper, Genlmsghdr<u8, u16>>(
        GenlId::from(family_id),   // nl_type
        NlmF::REQUEST,             // flags (add NlmF::ACK if you want explicit ACKs in older kernels)
        NlPayload::Payload(genlhdr),
    )?;

    // Drain responses so errors (incl. ACK errors) surface
    for msg in recv {
        let _ = msg?; // ignore contents, just validate success
    }

    Ok(())
}
