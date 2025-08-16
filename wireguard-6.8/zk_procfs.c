#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "zk_pending.h"

static int zk_proc_show(struct seq_file *m, void *v)
{
    return zk_pending_seq_show(m, v); // reuse DebugFS logic
}

static int zk_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, zk_proc_show, NULL);
}

static const struct proc_ops zk_proc_ops = {
        .proc_open = zk_proc_open,
        .proc_read = seq_read,
        .proc_lseek = seq_lseek,
        .proc_release = single_release,
};

void zk_procfs_init(void)
{
    proc_create("wgzk_pending", 0444, NULL, &zk_proc_ops);
}

void zk_procfs_exit(void)
{
    remove_proc_entry("wgzk_pending", NULL);
}
