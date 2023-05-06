#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include "shuffle.h"
#include "GOT_offset.h"



int init(){
	printf("\n\nndat[44] = %d\n", ndat[44]);
	printf("code_498's GOT_offset: %p\n", (void*) GOT_offset[ndat[44]]); //18180  11816  1476
	FILE* fp;
	char buffer[1024];
	char base_address[13];

	fp = fopen("/proc/self/maps", "r");
	if (fp == NULL) 
	{
		perror("Error opening file!\n");
		exit(1); 
	}

	while (fgets(buffer, 1024, fp) != NULL) 
	{
		//printf("%s", buffer);
		if(strstr(buffer, "/chals"))
		{
			//printf("%s", buffer);
			for(int i=0; i<12; i++)
				base_address[i] = buffer[i];
			base_address[12] = '\0';	
			break;	
		}	
	}
	printf("base_address in string: %s\n", base_address);		
	fclose(fp);

		
	//convert to hexadecimal and compare(add) pointers
	//https://stackoverflow.com/questions/33966152/strtoul-not-working-as-expected
	unsigned long int address_hex = strtol(base_address,NULL,16);
	void *GOT_p = (void*) address_hex + 0x17000;
	printf("base_address: %p, base_address GOT_p: %p\n", (void*) address_hex, GOT_p);
	
        if (mprotect(GOT_p, getpagesize()*2, PROT_WRITE) == -1) 
        {
		perror("Error mprotect!\n");
		exit(1);
        }	

	
	void *fHandle = dlopen("./libpoem.so", RTLD_LAZY);
	if (!fHandle) 
	{
		fprintf (stderr, "%s\n", dlerror());
		exit(1);
    	}
	dlerror();
	
	
	unsigned long int true_addr[1477];
	for(int i=0; i<1477; i++)   //i=44, ndat[44]=498
	{
		if(GOT_offset[ndat[i]] == 0)  
			continue;	        
		char code_num[9];
		sprintf(code_num, "code_%d", i); 
		true_addr[i] = (unsigned long int)dlsym(fHandle, code_num); 
		unsigned long int GOT_address_hex = address_hex + GOT_offset[ndat[i]];  
		if(i==44)
		{
			printf("%p\n", (void*) true_addr[i]);  //498's true_address is in true_addr[44]
			printf("%p\n", (void*) GOT_address_hex);  //498's GOT_address
		}
		*(unsigned long int *)GOT_address_hex = true_addr[i];	        
	}
	
	
	
	

	dlclose(fHandle);
	return 0;
}



// make
// make test
// python submit.py ./libsolver.so
