
obj-m     += kshram.o
ccflags-y += -DEXPORT_SYMTAB

all: kzalloc
	make -C ../dist/modulebuild M=$(PWD) modules

hello: kzalloc.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

clean:
	rm -f kzalloc
	make -C ../dist/modulebuild M=$(PWD) clean

