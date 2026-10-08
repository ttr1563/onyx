// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct super_block {
    unsigned int s_dev;
} __attribute__((preserve_access_index));

struct inode {
    unsigned long i_ino;
    struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct dentry {
    struct dentry *d_parent;
    struct inode *d_inode;
} __attribute__((preserve_access_index));

struct vfsmount;

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
    struct path f_path;
    unsigned int f_flags;
} __attribute__((preserve_access_index));

struct vm_area_struct {
    unsigned long vm_flags;
    struct file *vm_file;
} __attribute__((preserve_access_index));

enum osmanthus_action {
    OSMANTHUS_DELETE = 1,
    OSMANTHUS_RENAME = 2,
    OSMANTHUS_TRUNCATE = 3,
    OSMANTHUS_CHANGE_PERMISSIONS = 4,
    OSMANTHUS_WRITE = 5,
};

enum osmanthus_event_type {
    OSMANTHUS_EVENT_EXEC = 1,
    OSMANTHUS_EVENT_RESOURCE_BLOCKED = 2,
};

struct resource_key {
    unsigned long long inode;
    unsigned int device;
    unsigned int action;
};

struct boundary_key {
    unsigned long long inode;
    unsigned int device;
    unsigned int reserved;
};

struct osmanthus_event {
    unsigned long long timestamp_ns;
    unsigned long long inode;
    unsigned int event_type;
    unsigned int action;
    unsigned int device;
    unsigned int pid;
    unsigned int tgid;
    unsigned int uid;
    unsigned int gid;
    char comm[16];
    char filename[256];
    unsigned int reserved;
};

struct trace_event_raw_sys_enter {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
    long id;
    unsigned long args[6];
} __attribute__((preserve_access_index));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct resource_key);
    __type(value, unsigned char);
} osmanthus_protected_roots SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct boundary_key);
    __type(value, unsigned char);
} osmanthus_protected_boundaries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct resource_key);
    __type(value, unsigned long long);
} osmanthus_maintenance_leases SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, unsigned int);
    __type(value, unsigned char);
} osmanthus_monitored_uids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} osmanthus_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, unsigned int);
    __type(value, unsigned int);
} osmanthus_metadata SEC(".maps");

static __always_inline void fill_identity(struct osmanthus_event *event)
{
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    unsigned long long uid_gid = bpf_get_current_uid_gid();

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = (unsigned int)pid_tgid;
    event->tgid = pid_tgid >> 32;
    event->uid = (unsigned int)uid_gid;
    event->gid = uid_gid >> 32;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
}

static __always_inline void emit_blocked(const struct resource_key *key)
{
    struct osmanthus_event *event;

    event = bpf_ringbuf_reserve(&osmanthus_events, sizeof(*event), 0);
    if (!event)
        return;
    __builtin_memset(event, 0, sizeof(*event));
    fill_identity(event);
    event->event_type = OSMANTHUS_EVENT_RESOURCE_BLOCKED;
    event->inode = key->inode;
    event->device = key->device;
    event->action = key->action;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline int emit_exec(const char *filename)
{
    unsigned int uid = (unsigned int)bpf_get_current_uid_gid();
    unsigned char *enabled;
    struct osmanthus_event *event;

    enabled = bpf_map_lookup_elem(&osmanthus_monitored_uids, &uid);
    if (!enabled)
        return 0;
    event = bpf_ringbuf_reserve(&osmanthus_events, sizeof(*event), 0);
    if (!event)
        return 0;
    __builtin_memset(event, 0, sizeof(*event));
    fill_identity(event);
    event->event_type = OSMANTHUS_EVENT_EXEC;
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int write_protection_enabled(void)
{
    unsigned int key = 1;
    unsigned int *enabled = bpf_map_lookup_elem(&osmanthus_metadata, &key);

    return enabled && *enabled;
}

#define OSMANTHUS_MAX_ANCESTORS 256

struct guard_context {
    struct dentry *current;
    unsigned long long now;
    struct resource_key event_key;
    unsigned int action;
    int decision;
};

static long guard_dentry_step(unsigned int index, void *data)
{
    struct guard_context *context = data;
    struct dentry *current = context->current;
    struct inode *inode;
    struct super_block *superblock;
    struct dentry *parent;
    struct resource_key key = {};
    unsigned long long *lease_expiry;

    if (!current)
        return 1;
    inode = BPF_CORE_READ(current, d_inode);
    if (!inode)
        return 1;
    superblock = BPF_CORE_READ(inode, i_sb);
    if (!superblock)
        return 1;
    key.inode = BPF_CORE_READ(inode, i_ino);
    key.device = BPF_CORE_READ(superblock, s_dev);
    key.action = context->action;
    context->event_key = key;

    lease_expiry = bpf_map_lookup_elem(&osmanthus_maintenance_leases, &key);
    if (lease_expiry && context->now <= *lease_expiry) {
        context->decision = 0;
        return 1;
    }
    if (bpf_map_lookup_elem(&osmanthus_protected_roots, &key)) {
        context->decision = -EPERM;
        return 1;
    }
    parent = BPF_CORE_READ(current, d_parent);
    if (parent == current) {
        context->decision = 0;
        return 1;
    }
    context->current = parent;
    return 0;
}

static __always_inline int guard_dentry(struct dentry *start, unsigned int action)
{
    struct guard_context context = {
        .current = start,
        .now = bpf_ktime_get_ns(),
        .action = action,
        .decision = -ELOOP,
    };

    if (bpf_loop(OSMANTHUS_MAX_ANCESTORS, guard_dentry_step, &context, 0) < 0)
        context.decision = -ELOOP;
    if (context.decision)
        emit_blocked(&context.event_key);
    return context.decision;
}

struct mount_guard_context {
    struct dentry *current;
    struct resource_key event_key;
    int decision;
};

static long guard_mount_step(unsigned int index, void *data)
{
    struct mount_guard_context *context = data;
    struct dentry *current = context->current;
    struct inode *inode;
    struct super_block *superblock;
    struct dentry *parent;
    struct boundary_key key = {};

    if (!current)
        return 1;
    inode = BPF_CORE_READ(current, d_inode);
    if (!inode)
        return 1;
    superblock = BPF_CORE_READ(inode, i_sb);
    if (!superblock)
        return 1;
    key.inode = BPF_CORE_READ(inode, i_ino);
    key.device = BPF_CORE_READ(superblock, s_dev);
    context->event_key.inode = key.inode;
    context->event_key.device = key.device;
    context->event_key.action = 6;
    if (bpf_map_lookup_elem(&osmanthus_protected_boundaries, &key)) {
        context->decision = -EPERM;
        return 1;
    }
    parent = BPF_CORE_READ(current, d_parent);
    if (parent == current) {
        context->decision = 0;
        return 1;
    }
    context->current = parent;
    return 0;
}

static __always_inline int guard_mount_boundary(struct dentry *start)
{
    struct mount_guard_context context = {
        .current = start,
        .decision = -ELOOP,
    };

    if (bpf_loop(OSMANTHUS_MAX_ANCESTORS, guard_mount_step, &context, 0) < 0)
        context.decision = -ELOOP;
    if (context.decision)
        emit_blocked(&context.event_key);
    return context.decision;
}

SEC("lsm/sb_mount")
int BPF_PROG(osmanthus_sb_mount, const char *dev_name, const struct path *path,
             const char *type, unsigned long flags, void *data, int ret)
{
    if (ret)
        return ret;
    return guard_mount_boundary(BPF_CORE_READ(path, dentry));
}

SEC("lsm/move_mount")
int BPF_PROG(osmanthus_move_mount, const struct path *from_path,
             const struct path *to_path, int ret)
{
    if (ret)
        return ret;
    return guard_mount_boundary(BPF_CORE_READ(to_path, dentry));
}

SEC("lsm/path_unlink")
int BPF_PROG(osmanthus_path_unlink, const struct path *dir, struct dentry *dentry, int ret)
{
    if (ret)
        return ret;
    return guard_dentry(dentry, OSMANTHUS_DELETE);
}

SEC("lsm/path_rmdir")
int BPF_PROG(osmanthus_path_rmdir, const struct path *dir, struct dentry *dentry, int ret)
{
    if (ret)
        return ret;
    return guard_dentry(dentry, OSMANTHUS_DELETE);
}

SEC("lsm/path_rename")
int BPF_PROG(osmanthus_path_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry,
             unsigned int flags, int ret)
{
    int decision;

    if (ret)
        return ret;
    decision = guard_dentry(old_dentry, OSMANTHUS_RENAME);
    if (decision)
        return decision;
    return guard_dentry(BPF_CORE_READ(new_dir, dentry), OSMANTHUS_RENAME);
}

SEC("lsm/file_open")
int BPF_PROG(osmanthus_file_open, struct file *file, int ret)
{
    unsigned int flags;

    if (ret)
        return ret;
    flags = BPF_CORE_READ(file, f_flags);
    if (!(flags & O_TRUNC))
        return 0;
    return guard_dentry(BPF_CORE_READ(file, f_path.dentry), OSMANTHUS_TRUNCATE);
}

SEC("lsm/file_permission")
int BPF_PROG(osmanthus_file_permission, struct file *file, int mask, int ret)
{
    if (ret)
        return ret;
    if (!(mask & 0x00000002) || !write_protection_enabled())
        return 0;
    return guard_dentry(BPF_CORE_READ(file, f_path.dentry), OSMANTHUS_WRITE);
}

SEC("lsm/mmap_file")
int BPF_PROG(osmanthus_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int ret)
{
    if (ret)
        return ret;
    if (!file || !(prot & 0x2) || !(flags & 0x01) || !write_protection_enabled())
        return 0;
    return guard_dentry(BPF_CORE_READ(file, f_path.dentry), OSMANTHUS_WRITE);
}

SEC("lsm/file_mprotect")
int BPF_PROG(osmanthus_file_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret)
{
    struct file *file;
    unsigned long flags;

    if (ret)
        return ret;
    if (!(prot & 0x2) || !write_protection_enabled())
        return 0;
    flags = BPF_CORE_READ(vma, vm_flags);
    if (!(flags & 0x00000008))
        return 0;
    file = BPF_CORE_READ(vma, vm_file);
    if (!file)
        return 0;
    return guard_dentry(BPF_CORE_READ(file, f_path.dentry), OSMANTHUS_WRITE);
}

SEC("lsm/path_chmod")
int BPF_PROG(osmanthus_path_chmod, const struct path *path, unsigned short mode, int ret)
{
    if (ret)
        return ret;
    return guard_dentry(BPF_CORE_READ(path, dentry), OSMANTHUS_CHANGE_PERMISSIONS);
}

SEC("lsm/path_chown")
int BPF_PROG(osmanthus_path_chown, const struct path *path, unsigned int uid,
             unsigned int gid, int ret)
{
    if (ret)
        return ret;
    return guard_dentry(BPF_CORE_READ(path, dentry), OSMANTHUS_CHANGE_PERMISSIONS);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int osmanthus_execve(struct trace_event_raw_sys_enter *context)
{
    return emit_exec((const char *)context->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int osmanthus_execveat(struct trace_event_raw_sys_enter *context)
{
    return emit_exec((const char *)context->args[1]);
}

char LICENSE[] SEC("license") = "GPL";
