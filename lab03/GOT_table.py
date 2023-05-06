from pwn import *
elf = ELF('./chals')
print("main =", hex(elf.symbols['main']))
print("{:<12s} {:<8s} {:<8s}".format("Func", "GOT Offset", "Symbol Offset"))
list = 'unsigned long int GOT_offset[] = {'
for i in range(0, 1477):  #1477
    #for g in elf.got:
        if "code_"+str(i) in elf.got:
            #print("{:<12s} {:<8x}".format("code_"+str(i), elf.got["code_"+str(i)]))    
            list += (hex(elf.got["code_"+str(i)])) + ", "
        else:
            #print("{:<12s} {:<8x}".format("code_"+str(i), 0))    
            list += (hex(0)) + ", " 
        if(i == 1476):
            if "code_"+str(i) in elf.got:
                print("{:<12s} {:<8x}".format("code_"+str(i), elf.got["code_"+str(i)]))    
                list += (hex(elf.got["code_"+str(i)]))
            else:
                print("{:<12s} {:<8x}".format("code_"+str(i), 0))    
                list += (hex(0))
list += '};'                            
print(list)
