#!/usr/bin/env python
# coding=utf-8
from z3 import *
import sys
s = Solver()
a = BitVec("a", 32)
b = BitVec("b", 32)
c = BitVec("c", 32)
d = BitVec("d", 32)
e = BitVec("e", 32)
f = BitVec("f", 32)

g = BitVec("g", 32)
h = BitVec("h", 32)

i = BitVec("i", 32)

i=(((((0x1337*a+1)*b+1)*c+1)*d+1)*g+1)*h+1
s.add(a<256,b<256,c<256,d<256,g<256,h<256,i<=0x7eFFFFFF)
s.add(a>0,b>0,c>0,d>0,g>0,h>0,i>0)

tmp=int(sys.argv[1])
if(tmp>=32):
    s.add(i%62==61)
    tmp-=32
else:
    s.add((i+2)%62==0)

e=((b<<8)+a)^((d<<8)+c)^((h<<8)+g)
s.add((((e >> 10) ^((e ^ (e >> 5))&0xFF))&0x1f)==tmp)
f=0
for w in range(8):
    f=f+((a>>w)&0x1)
    f=f+((b>>w)&0x1)
    f=f+((c>>w)&0x1)
    f=f+((d>>w)&0x1)
    f=f+((g>>w)&0x1)
    f=f+((h>>w)&0x1)

s.add((f&0x1f)==tmp)

if(s.check()):
    m=s.model()
    print(m[a]+m[b]+m[c]+m[d]+m[g]+m[h])
