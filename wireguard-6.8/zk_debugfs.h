#ifndef WG_ZK_DEBUGFS_H
#define WG_ZK_DEBUGFS_H

#include <linux/types.h>
#include <linux/debugfs.h>
int zk_debugfs_init(struct dentry *parent);
void zk_debugfs_cleanup(void);
void zk_debugfs_update(const void *msg, size_t len);
#endif /* WG_ZK_DEBUGFS_H */
