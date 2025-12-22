# alloc-101 / Daily AlpacaHack

[EN](./README.md)

## チャレンジ概要

```
$ file chal
chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=41a3c65b95b39b730b0af349704ad7315274756d, for GNU/Linux 3.2.0, not stripped
```

[ソースコード](./chal.c)を読むとバイナリは4つの機能が実装されています.

1. allocate
2. free
3. read
4. allocate flag

更にバイナリはフラグの長さを`main`関数の先頭でユーザーに提供します.

### 1. allocate

```c
printf("size> ");
int size;
scanf("%d%*c",&size);
item = malloc(size);
printf("[DEBUG] item: %p\n",item);
```

ユーザーは任意サイズのオブジェクトを`malloc`を利用して割り当てることができます.
その後,ポインタを`*item`にセットします.

### 2. free

```c
assert(item != NULL);
free(item);
//item == NULL;
```

ユーザーは任意の`*item`が指す任意のオブジェクトを解放できます.

### 3. read

```c
assert(item != NULL);
puts(item);
```

ユーザーは`*item`が指す任意のオブジェクトを読み取れます.

### 4. allocate flag

```c
char *flag = malloc(f_sz);
printf("[DEBUG] flag: %p\n",flag);
fgets(flag,f_sz,f_ptr);
```

ユーザーはフラグを含むオブジェクトを`malloc`を利用して割り当てることができます.

## bug

バグはシンプルです. 行番号43の省略はUse-After-Freeを引き起こします.

### short PoC w/ debugging

何かを割り当てたあと, freeを選択します.
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

`*item`の値を確認します.
```
gef> x/gx &item
0x555555558030 <item>:  0x000055555555a490
```

結果のように`*item`は解放されたのにも関わらず引き続き割り当てたオブジェクトを指しています.

## strategy

一言で言うと, glibcは他の多くの割り当てシステム(例: slab, buddy, go runtime)のように割り当てのキャッシュシステムを持っています.

戦略は簡単です

1. flagと同じ長さのオブジェクトを割り当てる
	- glibcのキャッシュシステムは0x10 (16-byte)アライメントを矯正するため, アライメントしたサイズがアライメントしたフラグのサイズと同じになればどのような値でも良いです.
2. free
3. allocate flag
4. read

キャッシュシステムによりフラグは最初に割り当てたオブジェクトと同じアドレスに割り当てられます.

これにより, ポインタ`*item`を通してフラグを読み取れます.

