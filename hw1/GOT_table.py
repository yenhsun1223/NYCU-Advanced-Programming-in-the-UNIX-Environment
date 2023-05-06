from pwn import *
import psutil
import sys
if len(sys.argv) > 1:
	parent_pid = int(sys.argv[1]) 
parent_exe = os.readlink(f"/proc/{parent_pid}/exe")
#print("\nHere is GOT_table.py.")
#print("parent_exe: "+parent_exe)    
elf = ELF(parent_exe)
#print("{:<12s} {:<8s} {:<8s}".format("Func", "GOT", "Address"))            	
f = open("GOT_offset.txt", "w")
for i in ["open", "read", "write", "connect", "getaddrinfo", "system"]:
        test = 0
        for g in elf.got:
        	if(i==g):
        		#print("{:<12s} {:<8x} {:<8x}".format(g, elf.got[g], elf.symbols[g]))
        		f.write("{:x} ".format(elf.got[g]))
        		test = 1
        		break
        if(test==0):
        	f.write("0 ")       	
f.close()
            
