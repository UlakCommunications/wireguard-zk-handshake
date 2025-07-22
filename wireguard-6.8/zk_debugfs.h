#ifndef WG_ZK_DEBUGFS_H
#define WG_ZK_DEBUGFS_H

#include <linux/types.h>
#include <linux/debugfs.h>

/**
 * Initializes the debugfs file for ZK handshake dumping.
 * Call this inside device_debugfs_init().
 *
 * @param parent Parent dentry (e.g., wg->debug_dir)
 */
void zk_debugfs_init(struct dentry *parent);

/**
 * Removes the debugfs file.
 * Call this inside device_debugfs_cleanup().
 */
void zk_debugfs_cleanup(void);

/**
 * Updates the buffer exposed at /sys/kernel/debug/wireguard/zk_handshake.
 *
 * @param msg Pointer to raw handshake data (e.g., struct message_handshake_initiation_zk)
 * @param len Length of msg
 */
void zk_debugfs_update(const void *msg, size_t len);

#endif /* WG_ZK_DEBUGFS_H */
