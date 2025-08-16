// wgzk_genl.c

#include <linux/kernel.h>
#include <linux/netlink.h>
#include <net/genetlink.h>

#include "peer.h"
#include "zk_pending.h"
void wg_packet_send_handshake_response(struct wg_peer *peer);
extern struct hlist_head zk_pending_table[];
extern spinlock_t zk_lock;

//
// Attribute enum
//
enum {
	WGZK_ATTR_UNSPEC,
	WGZK_ATTR_PEER_INDEX,
	WGZK_ATTR_RESULT,
	__WGZK_ATTR_MAX,
};
#define WGZK_ATTR_MAX (__WGZK_ATTR_MAX - 1)

//
// Command enum
//
enum {
    WGZK_CMD_UNSPEC,
	WGZK_CMD_VERIFY,
    __WGZK_CMD_MAX,
};
#define WGZK_CMD_MAX (__WGZK_CMD_MAX - 1)

//
// Attribute policy
//
static const struct nla_policy wgzk_genl_policy[WGZK_ATTR_MAX + 1] = {
	[WGZK_ATTR_PEER_INDEX] = { .type = NLA_U32 },
	[WGZK_ATTR_RESULT]     = { .type = NLA_U8 },
};

//
// VERIFY handler
//
static int wgzk_verify_handler(struct sk_buff *skb, struct genl_info *info)
{
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
    if (result == 1 && entry->peer) {
        struct wg_peer *peer = entry->peer;
		/* Trigger a normal handshake response now that ZK is approved */
		/* If you wired Option B earlier, call the sender here: */
		        /* wg_packet_send_handshake_response(peer); */
		        net_dbg_ratelimited("WG-ZK: Proof accepted; will respond to %pISpf (idx=%u)\n",
		                            &peer->endpoint.addr, sender_index);
    } else {
        // ZK proof rejected
		pr_info("WG-ZK: Proof failed or rejected — dropping peer %u\n", sender_index);
		// Optionally: wg_peer_remove(entry->peer);
    }

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
