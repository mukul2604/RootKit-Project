obj-m += rootkit.o

all:
	gcc -Wall -Werror test_hide_proc.c -o test_hide_proc
	gcc -Wall -Werror test_elevate.c -o test_elevate	
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf test_hide_proc
	rm -rf test_elevate
