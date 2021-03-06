# 常见漏洞利用方式

## 0x001-栈迁移

程序中存在栈溢出，但是溢出的长度太短，只能覆盖到EBP和返回地址时，那么就需要用到栈迁移技术。

栈迁移需要覆盖EBP制造新栈帧空间，然后利用 **leave ; ret** 两个指令，劫持EIP/RIP，控制程序执行流程。

例如，一个程序的缓冲区到EBP的偏移为offset，则可以通过如下payload，将ebp地址覆盖为new_ebp地址，该new_ebp地址可以是bss段中的地址（如果将新栈空间转移到bss段中，需要注意与got表的位置，尽量往后移），
最后将返回地址覆盖为 **leave ; ret** 指令的地址。
```
payload = b"A" * offset + p64(new_ebp) + p64(leave_ret_addr)
```

程序函数结束会进行一次 **leave ; ret** 操作，此时会将ebp的值设置为new_ebp，EIP为leave_ret_addr，之后再次执行 **leave ; ret** 操作，就会将new_ebp位置处的第一个值赋值给EBP，第二个值赋值给EIP，也就是说此时需要在new_ebp中构造如下内容：
```
payload = p32(new_ebp) + p32(getshell_addr)
```

之后就可以控制程序执行流程。

## 0x002-Canary绕过

Canary特性：

1. 在同一个程序里，每个函数中的Canary值是一样的，也就是说可以在一个函数中泄漏Canary值，然后在另一个函数中使用Canary值完成栈溢出漏洞利用；
2. Canary最后两位一定是 "\x00"，也就是说如果函数中存在栈溢出，则可以将Canary的最后两位覆盖掉，那么就可以利用puts等函数将Canary的值打印出来；

## 0x003-格式化字符串

### 任意地址读取

![](1.png)

> %x : 以十六进制形式打印栈中 **数据A** 的值

> %d : 以十进制形式打印栈中 **数据A** 的值

> %p : 以指针形式（十六进制）打印栈中 **数据A** 的值

> %s : 以字符串形式打印栈中 **数据B** 的值

通过 **%n\$x** 可以打印栈中任意位置 **数据A** 的值，或者通过 **%n\$s** 可以打印栈中任意位置 **数据B** 的值，n为偏移量控制栈的位置，一般 n>=1。

也可以使用 **地址+%n$s** 打印任意地址中保存的内容，此时 **n** 为输入内容相对于 **printf** 的偏移量。

### 任意地址写入

> %c : 输出字符，可以配合 **%n** 使用

> %n : 把已经成功输出的字符个数写入对应的整型指针参数所指的变量中

例如，可以使用 **p32(0x804c044) + b"%10$n"**，将 4 写入 **0x804c044** 中，因为 **p32(0x804c044)** 打印出来是4个字符；

也可以使用 **p32(atoi_got) + b"%" + str(system_plt-4).encode() + b"c%10$n"** 将 **atoi** 函数的GOT地址修改为 **system** 函数的PLT地址。

pwntools提供了格式化字符串漏洞利用的函数 **fmtstr_payload**：
```
pwnlib.fmtstr.fmtstr_payload(offset, writes, numbwritten=0, write_size='byte')
```

1. offset即为栈中指向被改写区域指针相对格式化字符串指针的偏移（作为第几个参数）；
2. writes是一个字典，为要改写的值和目标值，即用value的值替换掉内存中key指向的区域；
3. numbwritten即为在之前已经输出的字符数；
4. write_size为mei每次改写的size，一般使用byte（hhn），以避免程序崩溃或连接断开。

## 0x004-堆溢出利用之泄露地址

1. 通过unsorted bin的特性（如果unsorted bin只有一个bin，它的fd和bk指针会指向同一个地址，这个地址是unsorted bin链表的头部，相对libc固定偏移0x3c4b78），可以先申请一个unsorted bin块，然后释放，通过读取unsorted bin中存放的内容，即可泄露libc地址；

## 0x005-堆漏洞利用之任意地址跳转

**__malloc_hook**

malloc函数会首先检查__malloc_hook的值。若不为0则会调用其中的地址。

可以通过fastbin attack攻击malloc_hook，fastbin在分配时并不检查对齐情况，可以将fastbin的fd设置为__malloc_hook-0x23，然后触发fastbin attack分配得到__malloc_hook上方的内存空间，最后将__malloc_hook写入one_gadget得到权限。

**__free_hook**

同__malloc_hook类似，在调用free函数时会先检验__free_hook的值。

但由于__free_hook上方都是0字节，不能直接通过fastbin_attack进行攻击，因此需要通过修改top free_hook上方，之后申请内存至__free_hook，并将内容修改为system或one_gadget地址。

fastbin数组在top chunk指针上方。可以通过free fastbin chunk修改fastbin数组的值使的fastbin attack可以实现。 存在限制要求堆的地址以0x56开头

**__realloc_hook**

有些情况下one_gadget因为环境原因全部都不可用，这时可以通过realloc_hook来调整堆栈环境使one_gadget可用。

realloc函数在函数起始会检查__realloc_hook的值是否为0，不为0则跳转至__realloc_hook指向的地址。__realloc_hook同__malloc_hook相邻，故可通过fastbin attack一同修改两个值。

将__malloc_hook劫持为realloc+offset，__realloc_hook劫持为onegadget，实际运行顺序：
> malloc -> malloc_hook -> realloc -> realloc_hook -> onegadget

由于realloc函数开头有大量的push指令，可根据情况调整偏移，使用push函数调整堆栈。

**io_overflow**

**io_finish**

**large bin attack修改free_hook**

## 0x006-堆漏洞利用之Unlink
