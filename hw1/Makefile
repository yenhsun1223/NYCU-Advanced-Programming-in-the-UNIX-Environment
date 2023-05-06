
PROGS	= sandbox.so

all: $(PROGS)

sandbox.so: sandbox.c
	gcc -o sandbox.so -shared -fPIC -ldl sandbox.c	

cleanup:
	rm -f *.o

clean:
	rm -f $(PROGS) *.o
	rm -rf __pycache__

