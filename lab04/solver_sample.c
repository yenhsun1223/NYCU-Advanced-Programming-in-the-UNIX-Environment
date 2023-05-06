#include <stdio.h>

typedef int (*printf_ptr_t)(const char *format, ...);

void solver(printf_ptr_t fptr) {
	char msg[16] = "hello, world!";

	fptr("canary : %llx\n", *((unsigned long long*)(msg + 0x18)));
	fptr("rbp : %llx\n", *((unsigned long long*)(msg + 0x20)));
	fptr("return_addr : %llx\n", *((unsigned long long*)(msg + 0x28)) + 0xab);
}


int main() {
	char fmt[16] = "** main = %p\n";
	printf(fmt, main);
	solver(printf);
	return 0;
}

// gcc -o solver_sample solver_sample.c
// gcc -g solver_sample.c -o solver_sample
// gdb
// ./solver_sample
