use anyhow::{bail, Context};
use neli::attr::Attribute;
use neli::consts::genl::CtrlCmd;
use neli::consts::nl::Nlmsg;
use neli::genl::Nlattr;
use neli::nl::{Nlmsghdr, NlmsghdrBuilder};
use neli::socket::asynchronous::NlSocketHandle;
use neli::{
    consts::{
        genl::CtrlAttr, // only needed if you parse ctrl replies elsewhere
        nl::{GenlId, NlmF},
        socket::NlFamily,
    },
    genl::{AttrType, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder},
    nl::NlPayload
    ,
    types::{Buffer, GenlBuffer},
    utils::Groups,
};

pub const WGZK_GENL: &str = "wgzk";
// pub const WGZK_VERSION: u8 = 1;
// pub const WGZK_CMD_VERIFY: u8 = 1;
pub const WGZK_ATTR_PEER_INDEX: u16 = 1;
pub const WGZK_ATTR_RESULT: u16 = 2;


// Your wireguard-zk constants (keep them in one place)
pub const WGZK_CMD_SET_PROOF: u8 = 2;
pub const WGZK_ATTR_PEER_ID: u16 = 3;
pub const WGZK_ATTR_R: u16 = 4;
pub const WGZK_ATTR_S: u16 = 5;


pub const WGZK_CMD_VERIFY_ACK: u8 = 1;

async fn resolve_family_id(sock: &mut NlSocketHandle, name: &str) -> anyhow::Result<u16> {
    let mut attrs: GenlBuffer<CtrlAttr, Buffer> = GenlBuffer::new();

    // NUL-terminated family name ("wgzk\0")
    let mut namez = Vec::with_capacity(name.len() + 1);
    namez.extend_from_slice(name.as_bytes());
    namez.push(0);

    // Typed attr/buffer: CtrlAttr + Buffer
    let name_attr: Nlattr<CtrlAttr, Buffer> = NlattrBuilder::<CtrlAttr, Buffer>::default()
        .nla_type(AttrType::from(u16::from(CtrlAttr::FamilyName))) // <-- u16'dan AttrType<CtrlAttr>
        .nla_payload(Buffer::from(namez))
        .build()?;

    attrs.push(name_attr);

    // CTRL_CMD_GETFAMILY v2
    let genlhdr = GenlmsghdrBuilder::default()
        .cmd(CtrlCmd::Getfamily)
        .version(2)
        .attrs(attrs)
        .build()?;

    let req = NlmsghdrBuilder::default()
        .nl_type(GenlId::Ctrl)
        .nl_flags(NlmF::REQUEST | NlmF::ACK)
        .nl_payload(NlPayload::Payload(genlhdr))
        .build()?;

    sock.send(&req).await.context("ctrl send failed")?;

    // ACK may come first; then the NEWFAMILY payload with attrs.
    loop {
        let (iter, _) = sock.recv().await.context("ctrl recv failed")?;
        for msg in iter {
            let msg: Nlmsghdr<u16, Genlmsghdr<CtrlCmd, CtrlAttr>> = msg?;
            if *msg.nl_type() == u16::from(Nlmsg::Error) {
                if let NlPayload::Err(e) = msg.nl_payload() {
                    if *e.error() != 0 {
                        bail!("genl ctrl getfamily failed: {}", e);
                        }
                    }
                continue;
                }
            if let NlPayload::Payload(p) = msg.nl_payload() {
                for a in p.attrs().iter() {
                    // Look at the *response* attr type:
                    if let _ty @ CtrlAttr::FamilyId = *a.nla_type().nla_type() {
                        let id: u16 = a.get_payload_as()?;
                        return Ok(id);
                }
                    }
                }
            }
        }
    }

/// VERIFY_ACK
pub async fn send_verify_ack(
    family: &str,
    genl_version: u8, // should be 1 for your wgzk family
    peer_index: u32,
    result: u8,
) -> anyhow::Result<()> {


    let mut sock = NlSocketHandle::connect(NlFamily::Generic, None, Groups::empty())?;

    let fam_id = resolve_family_id(&mut sock, family).await?;
    eprintln!("family '{}' resolved to id {}", family, fam_id);

    // Build attrs (your family uses u16 attr numbers)
    let a1: Nlattr<u16, Buffer> = NlattrBuilder::default()
        .nla_type(AttrType::from(WGZK_ATTR_PEER_INDEX))
        .nla_payload(Buffer::from(peer_index.to_ne_bytes().to_vec()))
        .build()?;

    let a2: Nlattr<u16, Buffer> = NlattrBuilder::default()
        .nla_type(AttrType::from(WGZK_ATTR_RESULT))
        .nla_payload(Buffer::from(vec![result]))
        .build()?;
    let mut attrs: GenlBuffer<u16, Buffer> = GenlBuffer::new();
    // attribute’ları ekle
    attrs.push(a1);
    attrs.push(a2);


    let genlhdr = GenlmsghdrBuilder::default()
        .cmd(WGZK_CMD_VERIFY_ACK)
        .version(genl_version) // pass 1
        .attrs(attrs)
        .build()?;


    let nlhdr = NlmsghdrBuilder::default()
        .nl_type(fam_id)
        .nl_flags(NlmF::REQUEST | NlmF::ACK)
        .nl_payload(NlPayload::Payload(genlhdr))
        .build()?;

    sock.send(&nlhdr).await.context("send failed")?;

    // Accept any of: ACK (Err code=0), Ack, Done, or a genl payload.
    loop {
        let (iter, _) = sock.recv().await.context("recv failed")?;
        for msg in iter {
            let msg: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = msg?;
            match (*msg.nl_type()).into() {
                Nlmsg::Error => match msg.nl_payload() {
                    NlPayload::Err(e) => {
                        if *e.error() == 0 {
                        println!("VERIFY_ACK sent ✅");
                            return Ok(());
                        } else {
                            bail!("Kernel returned NLMSG_ERROR: {}", e);
                        }
                    }
                NlPayload::Ack(_) | NlPayload::Empty => {
                    println!("VERIFY_ACK sent ✅");
                    return Ok(());
                }
                _ => {
                    // bazı çekirdeklerde Error tipiyle farklı payload döner
                    println!("VERIFY_ACK sent ✅ (non-standard ACK payload)");
                    return Ok(());
                }
            },
            Nlmsg::Done => {
                println!("VERIFY_ACK sent ✅ (DONE)");
                return Ok(());
            }
                _ => {
                    if let NlPayload::Payload(_) = msg.nl_payload() {
                    println!("VERIFY_ACK handled ✅ (reply payload)");
                        return Ok(());
                    }
                // değilse okumaya devam
                }
            }
        }
    }
}


/// Send WGZK_CMD_SET_PROOF(peer_id, R, S) to the kernel
pub async fn send_set_proof(
    family_name: &str,
    version: u8,
    peer_id: u64,
    r: &[u8; 32],
    s: &[u8; 32],
)   {
    let mut sock = NlSocketHandle::connect(NlFamily::Generic, None, Groups::empty())
        .context("connect generic netlink for SET_PROOF").unwrap();

    let fam_id = resolve_family_id(&mut sock, family_name).await.unwrap();
    eprintln!("family '{}' resolved to id {}", family_name, fam_id);

    let mut attrs: GenlBuffer<u16, Buffer> = GenlBuffer::new();

    // Build attrs (your family uses u16 attr numbers)
    let a1: Nlattr<u16, Buffer> = NlattrBuilder::default()
        .nla_type(AttrType::from(WGZK_ATTR_PEER_ID))
        .nla_payload(Buffer::from(peer_id.to_ne_bytes().to_vec()))
        .build().unwrap();
    attrs.push(a1);
    let a2: Nlattr<u16, Buffer> = NlattrBuilder::default()
        .nla_type(AttrType::from(WGZK_ATTR_R))
        .nla_payload(Buffer::from(r.to_vec()))
        .build().unwrap();
    attrs.push(a2);
    let a2: Nlattr<u16, Buffer> = NlattrBuilder::default()
        .nla_type(AttrType::from(WGZK_ATTR_S))
        .nla_payload(Buffer::from(s.to_vec()))
        .build().unwrap();
    attrs.push(a2);

    let genlhdr = GenlmsghdrBuilder::default()
        .cmd(WGZK_CMD_SET_PROOF)
        .version(version) // pass 1
        .attrs(attrs)
        .build().unwrap();

    let nlhdr = NlmsghdrBuilder::default()
        .nl_type(fam_id)
        .nl_flags(NlmF::REQUEST)
        .nl_payload(NlPayload::Payload(genlhdr))
        .build().unwrap();

    sock.send(&nlhdr).await.context("send failed").unwrap();

}