use anyhow::{bail, Context};
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
use neli::attr::Attribute;
use neli::consts::genl::CtrlCmd;
use neli::consts::nl::Nlmsg;
use neli::genl::Nlattr;
use neli::nl::{Nlmsghdr, NlmsghdrBuilder};
use neli::socket::asynchronous::NlSocketHandle;

const WGZK_GENL: &str = "wgzk";
const WGZK_VERSION: u8 = 1;
const WGZK_CMD_VERIFY: u8 = 1;
const WGZK_ATTR_PEER_INDEX: u16 = 1;
const WGZK_ATTR_RESULT: u16 = 2;

/// VERIFY_ACK
pub async fn send_verify_ack(
    family: &str,
    genl_version: u8,
    peer_index: u32,
    result: u8,
) -> anyhow::Result<()> {
    const WGZK_CMD_VERIFY_ACK: u8 = 1;
    const WGZK_ATTR_PEER_INDEX: u16 = 1;
    const WGZK_ATTR_RESULT: u16 = 2;

    let mut sock = NlSocketHandle::connect(NlFamily::Generic, None, Groups::empty())?;

    let fam_id = resolve_family_id(&mut sock, family).await?;
    eprintln!("family '{}' resolved to id {}", family, fam_id);



    use neli::genl::{AttrType, Nlattr};
    use neli::types::{Buffer, GenlBuffer};

    // constants
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
        .version(genl_version)
        .attrs(attrs)
        .build()?;


    let nlhdr = NlmsghdrBuilder::default()
        .nl_type(fam_id)
        .nl_flags(NlmF::REQUEST | NlmF::ACK)
        .nl_payload(NlPayload::Payload(genlhdr))
        .build()?;

    sock.send(&nlhdr).await.context("send failed")?;

    // let (iter, _) = sock.recv().await.context("recv failed")?;
    // for msg in iter {
    //     let msg: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = msg?;
    //     if matches!((*msg.nl_type()).into(), Nlmsg::Error) {
    //         eprintln!("got ACK");
    //         return Ok(());
    //     }
    // }
    //

    let (iter, _) = sock.recv().await?;
    for msg in iter {
        let msg: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = msg?;
        if *msg.nl_type() == u16::from(Nlmsg::Error) {
            match msg.nl_payload() {
                NlPayload::Err(e) => {
                    let code: i32 = *e.error();
                    if code == 0 {
                        // // Optional: pull extended ack text if present
                        // if let Some(human_msg) = e
                        //     .ext_ack()
                        //     .iter()
                        //     .find(|a| a.nla_type() == neli::consts::nl::NlmsgerrAttr::Msg)
                        //     .and_then(|a| std::str::from_utf8(a.nla_payload().as_ref()).ok())
                        // {
                        //     eprintln!("netlink error {}: {}", code, human_msg);
                        // }
                        //
                        // let errno = -code; // kernel sends negative errno
                        // let io_err = std::io::Error::from_raw_os_error(errno);
                        // anyhow::bail!("netlink error {} ({})", code, io_err);
                        return Ok(());
                    } else {
                        bail!("Kernel returned NLMSG_ERROR: {}", e);
                    }
                }
                _ => bail!("Expected NLMSG_ERROR payload, got something else"),
            }
        }
    }
    // if you want to be tolerant, allow no-ack success for unicast genl ops:
    bail!("no ACK (NLMSG_ERROR) received from kernel");

}


async fn resolve_family_id(sock: &mut NlSocketHandle, name: &str) -> anyhow::Result<u16> {
    // NUL-terminated family name ("wgzk\0")
    let mut namez = Vec::with_capacity(name.len() + 1);
    namez.extend_from_slice(name.as_bytes());
    namez.push(0);

    // Typed attr/buffer: CtrlAttr + Buffer
    let name_attr: Nlattr<CtrlAttr, Buffer> = NlattrBuilder::<CtrlAttr, Buffer>::default()
        .nla_type(AttrType::from(u16::from(CtrlAttr::FamilyName))) // <-- u16'dan AttrType<CtrlAttr>
        .nla_payload(Buffer::from(namez))
        .build()?;

    let mut attrs: GenlBuffer<CtrlAttr, Buffer> = GenlBuffer::new();
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

    // Multipart olabilir: önce ACK (NLMSG_ERROR code=0), sonra NEWFAMILY payload’ı
    loop {
        let (iter, _) = sock.recv().await.context("ctrl recv failed")?;
        for msg in iter {
            let msg: Nlmsghdr<u16, Genlmsghdr<CtrlCmd, CtrlAttr>> = msg?;

            // ACK (NLMSG_ERROR code=0)
            if *msg.nl_type() == u16::from(Nlmsg::Error) {
                if let NlPayload::Err(e) = msg.nl_payload() {
                    if *e.error() != 0 {
                        bail!("genl ctrl getfamily failed: {}", e);
                    }
                }
                continue;
            }

            // NEWFAMILY cevabı: id’yi çek
            if let NlPayload::Payload(p) = msg.nl_payload() {
                for a in p.attrs().iter() {
                    // Burada "cevaptaki" attr'ı kontrol ediyoruz
                    if let CtrlAttr::FamilyId = *a.nla_type().nla_type() {
                        let id: u16 = a.get_payload_as()?;
                        return Ok(id);
                    }
                }
            }
        }
        // id bu batch’te gelmediyse recv'e devam et
    }
}




