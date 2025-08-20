#ifndef WG_ZK_DEBUGFS_H
#define WG_ZK_DEBUGFS_H

#include <linux/types.h>
#include <linux/debugfs.h>
#include <linux/debugfs.h>
#include <linux/dcache.h>   /* for debugfs_lookup() */

int zk_debugfs_init(struct dentry *parent);
void zk_debugfs_cleanup(void);
void zk_debugfs_update(const void *msg, size_t len);
void zk_publish_handshake(const u8 in96[96]);
#endif /* WG_ZK_DEBUGFS_H */
