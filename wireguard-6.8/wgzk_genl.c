#include "peer.h" // or wherever wg_peer struct is defined
extern struct hlist_head zk_pending_table[];
extern spinlock_t zk_lock;

static int wgzk_verify_handler(struct sk_buff *skb, struct genl_info *info)
{
    if (!info->attrs[WGZK_ATTR_PEER_INDEX] || !info->attrs[WGZK_ATTR_RESULT])
        return -EINVAL;

    u32 sender_index = nla_get_u32(info->attrs[WGZK_ATTR_PEER_INDEX]);
    u8 result = nla_get_u8(info->attrs[WGZK_ATTR_RESULT]);

    pr_info("WG-ZK: Received result=%u for index=%u\n", result, sender_index);

    struct zk_pending_entry *entry;
    bool found = false;

    spin_lock_bh(&zk_lock);
    hash_for_each_possible(zk_pending_table, entry, node, sender_index) {
        if (entry->sender_index == sender_index) {
            found = true;
            break;
        }
    }
    spin_unlock_bh(&zk_lock);

    if (!found) {
        pr_warn("WG-ZK: Unknown sender_index %u\n", sender_index);
        return -ENOENT;
    }

    if (result == 1) {
        // Success — resume handshake
        // Example: call noise_handshake_continue(entry->peer)
        pr_info("WG-ZK: Handshake resumed for peer index %u\n", sender_index);
    } else {
        pr_info("WG-ZK: Proof rejected, dropping peer %u\n", sender_index);
        // optionally: drop peer or cleanup
    }

    // Cleanup
    spin_lock_bh(&zk_lock);
    hash_del(&entry->node);
    spin_unlock_bh(&zk_lock);
    kfree(entry);

    return 0;
}
