use neli::{
    attr::Nlattr,
    consts::{genl::*, nl::*, socket::NlFamily},
    genl::{Genlmsghdr, GenlId},
    nl::Nlmsghdr,
    socket::NlSocketHandle,
    types::GenlBuffer,
};

const WGZK_GENL: &str = "wgzk_genl";
const WGZK_VERSION: u8 = 1;
const WGZK_CMD_VERIFY: u8 = 1;
const WGZK_ATTR_PEER_INDEX: u16 = 1;
const WGZK_ATTR_RESULT: u16 = 2;

pub fn send_wgzk_ack(peer_index: u32, result: u8) -> Result<(), Box<dyn std::error::Error>> {
    let mut sock = NlSocketHandle::connect(NlFamily::Generic, None, &[])?;
    let family_id = sock.resolve_genl_family(WGZK_GENL)?;

    let mut attrs = GenlBuffer::new();
    attrs.push(Nlattr::new(false, false, WGZK_ATTR_PEER_INDEX, peer_index)?);
    attrs.push(Nlattr::new(false, false, WGZK_ATTR_RESULT, result)?);

    let genlhdr = Genlmsghdr::new(Cmd::from(WGZK_CMD_VERIFY), WGZK_VERSION, attrs);
    let nlhdr = Nlmsghdr::new(None, GenlId::Ctrl, NlmF::REQUEST, None, None, genlhdr);
    sock.send(nlhdr)?;
    Ok(())
}
