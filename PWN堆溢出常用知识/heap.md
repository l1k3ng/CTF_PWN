## 0x001-堆分配中的bins

### fastbins

fastbins为单向链表，采用LIFO（后进先出）的方式。

### unsortedbin

来源：
1. 当一个较大的 **chunk** 被分割成两半后，如果剩下的部分大就会被放到 **unsortedbin** 中。
2. 释放一个不属于 **fastbin** 的 **chunk**，并且该 **chunk** 不和 **top chunk** 紧邻时，该 **chunk** 会被首先放到 **unsortedbin** 中。
3. 当进行 malloc_consolidate 时，如果不是和 **top chunk** 紧邻的话，可能会把合并后的 **chunk** 放到 **unsortedbin** 中。

使用：
1. **unsortedbin** 在使用的过程中，采用的遍历顺序是FIFO，即插入的时候插入到 **unsortedbin** 的头部，取出的时候从链表尾获取。
2. 在程序 malloc 时，如果在 **fastbin、smallbin** 中找不到对应大小的 **chunk**，就会尝试从 **unsortedbin** 中寻找 **chunk**。如果取出来的 **chunk** 大小刚好满足，就会直接返回给用户，否则就会把多余的 **chunk** 分别插入到对应的 **bin** 中。

**unsortedbin** 有一个特性，就是如果 **unsortedbin** 只有一个bin ，它的 **fd** 和 **bk** 指针会指向同一个地址（ **unsortedbin** 链表的头部），这个地址相对 **libc** 固定偏移 **0x3c4b78** ，所以得到这个 **fd** 的值，然后减去固定偏移，即可得到 **libc** 的基地址。

### smallbins

### largebins
