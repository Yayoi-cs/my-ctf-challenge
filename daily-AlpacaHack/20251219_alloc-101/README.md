# alloc-101 / Daily AlpacaHack

[JA](./JA.md)

## Quick overview

```
$ file chal
chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=41a3c65b95b39b730b0af349704ad7315274756d, for GNU/Linux 3.2.0, not stripped
```

According to the [source code](./chal.c), the binary implements 4 functions named:
1. allocate
2. free
3. read
4. allocate flag

Also, the binary provides the flag's length to the user at the start of function:`main`.

### 1. allocate

```c
printf("size> ");
int size;
scanf("%d%*c",&size);
item = malloc(size);
printf("[DEBUG] item: %p\n",item);
```

User can allocate arbitrary size object using `malloc`.
Then set the pointer to `*item`.

### 2. free

```c
assert(item != NULL);
free(item);
//item == NULL;
```

User can free the object pointed by `*item`.

### 3. read

```c
assert(item != NULL);
puts(item);
```

User can read the object pointed by `*item`.

### 4. allocate flag

```c
char *flag = malloc(f_sz);
printf("[DEBUG] flag: %p\n",flag);
fgets(flag,f_sz,f_ptr);
```

User can allocate a flag-contained object using `malloc`.

## bug

The bug is simple. Omitting line:43 occurs Use-After-Free.

### short PoC w/ debugging

select free after allocate something.
```
file information: 32 bytes
1. allocate
2. free
3. read
4. allocate flag
choice> 1
size> 32
[DEBUG] item: 0x55555555a490
choice> 2
choice> 
```

check the value of `*item`.
```
gef> x/gx &item
0x555555558030 <item>:  0x000055555555a490
```

as the result, `*item` still points to what we allocated, even though it has been freed.

## strategy

In a nutshell, glibc has a cache system of heap allocation as most of the allocating systems (e.g., slab, buddy, go runtime).

The strategy is simple.

1. allocate the same byte as flag length.
	- Due to the glibc's caching system enforcing 0x10 (16-byte) alignment, any chunk size is acceptable provided that the aligned size equals the aligned flag size.
2. free
3. allocate flag
4. read

'Cause of the cache system, the address of flag will be same as what allocated at first.

This mean we can read flag though `*item`.


