obj-m += diamorphine.o 
diamorphine-objs := ./src/diamorphine.o ./src/hooks.o  
# CC = gcc -Wall 
KVERSION = $(shell uname -r)

all:
		make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
		make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean