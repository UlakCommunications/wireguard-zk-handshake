// wgzk_genl.c

#include <linux/kernel.h>
#include <linux/netlink.h>
#include <net/genetlink.h>

#include "peer.h"
#include "zk_pending.h"
#include "wgzk_genl.h"
#include "zk_proof.h"

struct wg_peer *wg_noise_handshake_consume_initiation(void *raw_msg,
                                                      struct wg_device *wg);
void wg_packet_send_handshake_response(struct wg_peer *peer);
static int wgzk_set_proof_handler(struct sk_buff *skb, struct genl_info *info);

extern struct hlist_head zk_pending_table[];
extern spinlock_t zk_lock;

//
// Attribute enum
//
enum {
	WGZK_ATTR_UNSPEC,
	WGZK_ATTR_PEER_INDEX,
	WGZK_ATTR_RESULT,
    /* new: for setting proof */
    WGZK_ATTR_PEER_ID,   /* NLA_U64: peer->internal_id */
    WGZK_ATTR_R,         /* NLA_BINARY, len=32 */
    WGZK_ATTR_S,         /* NLA_BINARY, len=32 */
	__WGZK_ATTR_MAX,
};
#define WGZK_ATTR_MAX (__WGZK_ATTR_MAX - 1)

//
// Command enum
//
enum {
    WGZK_CMD_UNSPEC,
	WGZK_CMD_VERIFY,
    /* new */
    WGZK_CMD_SET_PROOF,
    __WGZK_CMD_MAX,
};
#define WGZK_CMD_MAX (__WGZK_CMD_MAX - 1)

//
// Attribute policy
//
static const struct nla_policy wgzk_genl_policy[WGZK_ATTR_MAX + 1] = {
	[WGZK_ATTR_PEER_INDEX] = { .type = NLA_U32 },
	[WGZK_ATTR_RESULT]     = { .type = NLA_U8 },
    [WGZK_ATTR_PEER_ID]    = { .type = NLA_U64 },
    [WGZK_ATTR_R]          = { .type = NLA_BINARY, .len = 32 },
    [WGZK_ATTR_S]          = { .type = NLA_BINARY, .len = 32 },
};

//
// VERIFY handler
//
static int wgzk_verify_handler(struct sk_buff *skb, struct genl_info *info) {
    u32 sender_index;
    u8 result;
    struct zk_pending_entry *entry = NULL;

    if (!info->attrs[WGZK_ATTR_PEER_INDEX] || !info->attrs[WGZK_ATTR_RESULT])
        return -EINVAL;

    sender_index = nla_get_u32(info->attrs[WGZK_ATTR_PEER_INDEX]);
    result = nla_get_u8(info->attrs[WGZK_ATTR_RESULT]);

    pr_info("WG-ZK: Received ZK result=%u for index=%u\n", result, sender_index);

    /* Ask pending subsystem to remove & return the entry atomically */
    entry = zk_pending_take(sender_index);
    if (!entry) {
        pr_warn("WG-ZK: Unknown or expired sender_index=%u\n", sender_index);
        return -ENOENT;
    }

    // ZK proof accepted
    if (result == 1) {
        struct wg_peer *peer = NULL;
        if (entry->raw && entry->wg) {
            struct message_handshake_initiation *norm = (void *)entry->raw;
            norm->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION);
            /* Re-run the normal handshake path; it will decrypt static,
             * bind to the correct peer, and return it on success. */
            peer = wg_noise_handshake_consume_initiation(entry->raw, entry->wg);
        }
        if (!IS_ERR(peer) && peer) {
            wg_packet_send_handshake_response(peer);
            net_dbg_ratelimited("WG-ZK: Proof accepted; response sent to %pISpf (idx=%u)\n",
                                &peer->endpoint.addr, sender_index);
        } else {
            pr_warn("WG-ZK: Re-consume failed for idx=%u\n", sender_index);
        }
    } else {
        // ZK proof rejected
        pr_info("WG-ZK: Proof failed or rejected — dropping peer %u\n", sender_index);
        // Optionally: wg_peer_remove(entry->peer);
    }

    kfree(entry->raw);
    kfree(entry);
    return 0;
}

//
// Command dispatch table
//
static const struct genl_ops wgzk_genl_ops[] = {
	{
		.cmd = WGZK_CMD_VERIFY,
		.flags = 0,
		.policy = wgzk_genl_policy,
		.doit = wgzk_verify_handler,
	},
    {
        .cmd = WGZK_CMD_SET_PROOF,
        .flags = 0,
        .policy = wgzk_genl_policy,
        .doit = wgzk_set_proof_handler,
    },
};

//
// Family registration
//
static struct genl_family wgzk_genl_family = {
	.name     = "wgzk",
	.version  = 1,
	.maxattr  = WGZK_ATTR_MAX,
	.module   = THIS_MODULE,
	.ops      = wgzk_genl_ops,
	.n_ops    = ARRAY_SIZE(wgzk_genl_ops),
};

//
// Called by wireguard's wg_device_init()
//
int wgzk_genl_init(void)
{
	int ret = genl_register_family(&wgzk_genl_family);
	if (ret)
		pr_err("WG-ZK: Failed to register netlink family\n");
	else
		pr_info("WG-ZK: Generic Netlink interface registered\n");
	return ret;
}

void wgzk_genl_exit(void)
{
	genl_unregister_family(&wgzk_genl_family);
	pr_info("WG-ZK: Generic Netlink interface unregistered\n");
}

static int wgzk_set_proof_handler(struct sk_buff *skb, struct genl_info *info)
{
    u64 peer_id;
    u8 *r, *s;

    if (!info->attrs[WGZK_ATTR_PEER_ID] ||
        !info->attrs[WGZK_ATTR_R] ||
        !info->attrs[WGZK_ATTR_S])
        return -EINVAL;

    if (nla_len(info->attrs[WGZK_ATTR_R]) != 32 ||
        nla_len(info->attrs[WGZK_ATTR_S]) != 32)
        return -EINVAL;

    peer_id = nla_get_u64(info->attrs[WGZK_ATTR_PEER_ID]);
    r = nla_data(info->attrs[WGZK_ATTR_R]);
    s = nla_data(info->attrs[WGZK_ATTR_S]);

    zk_proof_set(peer_id, r, s);
    pr_info("WG-ZK: cached proof for peer_id=%llu\n",
            (unsigned long long)peer_id);
    return 0;
}
