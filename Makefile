obj-m += rootkit.o

all:
	gcc -Wall -Werror sleep.c -o sleep	
	gcc -Wall -Werror test_elevate.c -o test_elevate	
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf sleep
	rm -rf test_elevate
