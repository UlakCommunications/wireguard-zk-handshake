/* zk_procfs.h - WireGuard ZK procfs hooks */
#ifndef _ZK_PROCFS_H
#define _ZK_PROCFS_H

/* Initialize ZK-related /proc entries */
void zk_procfs_init(void);

/* Clean up /proc entries */
void zk_procfs_exit(void);

#endif /* _ZK_PROCFS_H */
