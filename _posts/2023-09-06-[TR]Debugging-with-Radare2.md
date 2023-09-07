---
title: [TR]Debugging with Radare2
published: true
---

 
<div style="text-align:center"><img src="/assets/radare2.jpg" alt="Radare2" ></div>

Eğer ELF dosyasını hata ayıklamak istiyorsanız, IDA ve Ghidra araçları yerine Radare2'yi kullanmayı düşünebilirsiniz. Şahsen, Radare2'nin bazı durumlarda hata ayıklama işlemini kolaylaştırdığına inanıyorum. Eğer benim gibi bir Linux kullanıcısıysanız ve tersine mühendislikle ilgileniyorsanız, terminal kolaylığından bu aracı kullanabilirsiniz.

Şimdi, stmctf17 yarışmasında kullanılan cProjem sorusunun çözümünü göstereceğim. Programı [buradan](assets/cProjem) indirebilirsiniz.

### [](#header-3)Solution

Programı ilk çalıştırdığımızda bizi bir kaç seçenek karşılıyor. İlk seçeneği seçtiğimizde ise bizden bir şifre isteniyor. Flag'ın bu kısımda olduğunu anlıyoruz.

```
┌──(alper㉿nobody)-[~/Masaüstü]
└─$ ./cProjem    
C Dersi Proje #435
---------------------
1. Gizli C Projem
2. Fi #
3. STMCTF{}
4. Yardim Et
5. EXIT
Hosgeldin sayin yarismaci, simdi ne yapmak istersin? 1
Sifreyi alayim? secret
OLMADI 435
"Dogru zamanda, dogru yerde olmamaklardan olusur her zaman hayat."
```

`radare2` ile hata ayıklama modunda açıp `aaaa` komutunu kullanarak programın analiz edilmesini sağladıktan sonra `afl` komutunu kullanarak fonksiyonları listeleyebiliriz.

```
┌──(alper㉿nobody)-[~/Masaüstü]
└─$ r2 -d cProjem 
[0x7f1dd790f100]> aaaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Skipping type matching analysis in debugger mode (aaft)
[x] Propagate noreturn information (aanr)
[x] Finding function preludes
[x] Enable constraint types analysis for variables
[0x7f1dd790f100]> afl
0x004007f0    1 42           entry0
0x00400650    1 6            sym.imp.__libc_start_main
0x00400620    1 6            sym.imp.putchar
0x00400630    1 6            sym.imp.puts
0x00400640    1 6            sym.imp.__stack_chk_fail
0x00400660    1 6            sym.imp.srand
0x00400670    1 6            sym.imp.time
0x00400680    1 6            sym.imp.__printf_chk
0x00400690    1 6            sym.imp.__isoc99_scanf
0x004006a0    1 6            sym.imp.exit
0x004006b0    1 6            sym.imp.rand
0x004006d0   11 288          main
0x004009c0   13 608  -> 597  fcn.004009c0
0x004008f0    5 93           fcn.004008f0
0x00400c20   35 590          fcn.00400c20
0x00400970    3 65   -> 55   fcn.00400970
0x004008c0    8 134  -> 90   entry.init0
0x004008a0    3 28           entry.fini0
0x00400820    4 50   -> 41   fcn.00400820
0x7f1dd78f9af0   65 1242 -> 1213 fcn.7f1dd78f9af0
0x7f1dd78fa220   52 920  -> 860  fcn.7f1dd78fa220
0x7f1dd78fa5c0   67 1525 -> 1468 fcn.7f1dd78fa5c0
0x7f1dd78fb580   36 1010         fcn.7f1dd78fb580
0x7f1dd78fb9e0  455 9707 -> 9518 fcn.7f1dd78fb9e0
0x7f1dd79023e0   59 1870 -> 1823 fcn.7f1dd79023e0
0x7f1dd7902f90  351 8680 -> 6997 fcn.7f1dd7902f90
0x7f1dd79059f0   89 63685 -> 1526 fcn.7f1dd79059f0
0x7f1dd790973b    1 18           fcn.7f1dd790973b
0x7f1dd7907040   28 4133 -> 584  fcn.7f1dd7907040
0x7f1dd790f760   26 522  -> 506  fcn.7f1dd790f760
```

Bu adımdan sonra fonksiyonları tek tek inceleyebiliriz. Ancak bu işlem uzun sürebileceğinden, programı çalıştırdığımızda karşımıza çıkan `Sifreyi alayim?` dizesini aratırsak bizi ilgili işleve yönlendirecektir. `izz` komutu ile `Sifreyi alayim?` dizesini bulduktan sonra `axt` komutu ile adresini öğreniyoruz ve `s` komutu ile o adrese sıçrıyoruz.

![izz](/assets/izz.png)

`pdf` ile işlevin içeriğini görüntülediğimizde bazı değerlerin kaydedildiğini görüyoruz.

![mov](/assets/mov.png)

Biraz daha incelediğimizde değerlerin `xor` işlemine tabi tutulduğunu görüyoruz. `0x00400b9f` adresine çalışma zamanında değerleri görebilmek için `db 0x00400b9f` komutu ile `breakpoint` koyuyoruz.

![xor](/assets/xor.png)

Şimdi debug işlemine başlayabiliriz. `dc` ile programı çalıştırdıktan sonra programımızın `breakpoint` koyduğumuz yere gelmesini sağlıyoruz.

```
[0x004009c0]> dc
C Dersi Proje #463
---------------------
1. Gizli C Projem
2. Fi #
3. STMCTF{}
4. Yardim Et
5. EXIT
Hosgeldin sayin yarismaci, simdi ne yapmak istersin? 1
Sifreyi alayim? secret
hit breakpoint at: 0x400b9f
[0x00400b9f]>
```

`pdf` komutu ile incelerken `movsx edx, byte [rsp + rax + 0x120]` kodu dikkatimizi çekiyor. `rsp + rax + 0x120` bellek adresinin değerini görebilmek için `px @ rsp + rax + 0x120` komutunu kullanıyoruz ve daha önce gördüğümüz değerlerin burada tutulduğunu anlıyoruz.

```
[0x00400b9f]> px @ rsp + rax + 0x120
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7ffecd355310  5f57 5a49 515b 7c67 6661 6173 7774 5e2b  _WZIQ[|gfaaswt^+                                          
0x7ffecd355320  444e 676e 6763 486b 6a74 756e 5949 534c  DNgngcHkjtunYISL
0x7ffecd355330  4077 0000 0000 0000 ba0f 4000 0000 0000  @w........@.....
0x7ffecd355340  7365 6372 6574 0000 0000 0000 0000 0000  secret..........
0x7ffecd355350  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7ffecd355360  0000 0000 0000 0000 004a 274f 8fee 9b4d  .........J'O...M
0x7ffecd355370  cf01 0000 0000 0000 0100 0000 0000 0000  ................
0x7ffecd355380  0000 0000 0000 0000 c307 4000 0000 0000  ..........@.....
0x7ffecd355390  0000 0000 0100 0000 004a 274f 8fee 9b4d  .........J'O...M
0x7ffecd3553a0  b854 35cd fe7f 0000 ca06 72d7 1d7f 0000  .T5.......r.....
0x7ffecd3553b0  a054 35cd fe7f 0000 d006 4000 0000 0000  .T5.......@.....
0x7ffecd3553c0  4000 4000 0100 0000 b854 35cd fe7f 0000  @.@......T5.....
0x7ffecd3553d0  b854 35cd fe7f 0000 723d b70b 111e 5c74  .T5.....r=....\t
0x7ffecd3553e0  0000 0000 0000 0000 c854 35cd fe7f 0000  .........T5.....
0x7ffecd3553f0  0000 0000 0000 0000 0070 92d7 1d7f 0000  .........p......
0x7ffecd355400  723d d5ac 7b84 a18b 723d b106 f5b0 678a  r=..{...r=....g.
```

`_WZIQ[|gfaaswt^+DNgngcHkjtunYISL@w` stringi şifrelenmiş bir şekilde tutuluyor ve karakterler tek tek alınıp `ecx` registerina kaydedilerek `xor` işlemine sokuluyor. `drr` komutu ile kayıtları görüntülediğimizde de `rcx` registerinda ilgili değerlerin tutulduğunu görüyoruz.

![drr](/assets/drr.png)

Sıradaki adım bu değerlerin ne ile xorlandığını bulmak olmalı. Breakpoint koyduğumuz yerdeki `r12 + rax*4` bellek adresi dikkatimizi çekiyor. `px @ r12 + rax*4` ile içeriğine baktığımızda bazı değerler görüyoruz. 

```
[0x00400b9f]> px @ r12 + rax*4
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7ffecd3551f0  0c00 0000 0200 0000 1700 0000 0900 0000  ................                                          
0x7ffecd355200  0500 0000 0600 0000 0700 0000 0800 0000  ................
0x7ffecd355210  0900 0000 0100 0000 1400 0000 0c00 0000  ................
0x7ffecd355220  1300 0000 0e00 0000 0100 0000 1000 0000  ................
0x7ffecd355230  1100 0000 1000 0000 0100 0000 0200 0000  ................
0x7ffecd355240  0600 0000 0c00 0000 1700 0000 1800 0000  ................
0x7ffecd355250  0500 0000 1000 0000 0700 0000 1c00 0000  ................
0x7ffecd355260  0600 0000 1e00 0000 1f00 0000 1800 0000  ................
0x7ffecd355270  0700 0000 0900 0000 cf01 0000 0000 0000  ................
0x7ffecd355280  2200 0000 0300 0000 0200 0000 0a00 0000  "...............
0x7ffecd355290  0300 0000 1d00 0000 1c00 0000 1400 0000  ................
0x7ffecd3552a0  1700 0000 0f00 0000 0a00 0000 1d00 0000  ................
0x7ffecd3552b0  0b00 0000 1500 0000 1500 0000 1300 0000  ................
0x7ffecd3552c0  1200 0000 1100 0000 0d00 0000 0200 0000  ................
0x7ffecd3552d0  0d00 0000 0400 0000 1500 0000 0f00 0000  ................
0x7ffecd3552e0  0a00 0000 1300 0000 0800 0000 1b00 0000  ................
[0x00400b9f]> px @ r12 + rax*4 + 32
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7ffecd355210  0900 0000 0100 0000 1400 0000 0c00 0000  ................                                          
0x7ffecd355220  1300 0000 0e00 0000 0100 0000 1000 0000  ................
0x7ffecd355230  1100 0000 1000 0000 0100 0000 0200 0000  ................
0x7ffecd355240  0600 0000 0c00 0000 1700 0000 1800 0000  ................
0x7ffecd355250  0500 0000 1000 0000 0700 0000 1c00 0000  ................
0x7ffecd355260  0600 0000 1e00 0000 1f00 0000 1800 0000  ................
0x7ffecd355270  0700 0000 0900 0000 cf01 0000 0000 0000  ................
0x7ffecd355280  2200 0000 0300 0000 0200 0000 0a00 0000  "...............
0x7ffecd355290  0300 0000 1d00 0000 1c00 0000 1400 0000  ................
0x7ffecd3552a0  1700 0000 0f00 0000 0a00 0000 1d00 0000  ................
0x7ffecd3552b0  0b00 0000 1500 0000 1500 0000 1300 0000  ................
0x7ffecd3552c0  1200 0000 1100 0000 0d00 0000 0200 0000  ................
0x7ffecd3552d0  0d00 0000 0400 0000 1500 0000 0f00 0000  ................
0x7ffecd3552e0  0a00 0000 1300 0000 0800 0000 1b00 0000  ................
0x7ffecd3552f0  0600 0000 0f00 0000 1800 0000 0d00 0000  ................
0x7ffecd355300  0800 0000 0a00 0000 0096 8cd7 1d7f 0000  ................
```

Bu değerlerin şifrelenmiş stringimiz ile `xor` işlemine sokulduğunu anlıyoruz. Değerler decimal formatta kullanılıyor ve `cf01` den itibaren 2 ye ayrılıyor. Deneme yanılma yoluyla biraz uğraştıktan sonra sıra sıra bu sayıların alındığını ve xor işlemine sokulduğunu anlıyoruz.

```
┌──(alper㉿nobody)-[~/Masaüstü]
└─$ python3
>>> chr(ord('_')^0x0c)
'S'
>>> chr(ord('W')^0x03)
'T'
>>> chr(ord('Z')^0x17)
'M'
>>> chr(ord('I')^0x0a)
'C'
>>> chr(ord('Q')^0x05)
'T'
>>> chr(ord('[')^0x1d)
'F'
>>> chr(ord('|')^0x07)
'{'
```

Geriye ufak bir script ile bayrağı almak kalıyor.

```
from pwn import xor

cipher = "_WZIQ[|gfaaswt^+DNgngcHkjtunYISL@w"
hex1 = "0c 02 17 09 05 06 07 08 09 01 14 0c 13 0e 01 10 11 10 01 02 06 0c 17 18 05 10 07 1c 06 1e 1f 18 07 09"
hex2 = "22 03 02 0a 03 1d 1c 14 17 0f 0a 1d 0b 15 15 13 12 11 0d 02 0d 04 15 0f 0a 13 08 1b 06 0f 18 0d 08 0a"
hex1_list= hex1.split(" ")
hex2_list = hex2.split(" ")

dec1 = list(map(lambda x: int(x, 16), hex1_list))
dec2 = list(map(lambda x: int(x, 16), hex2_list))

for i,letter in enumerate(cipher):
    if (i % 2) == 0: 
        print((xor(letter, dec1[i])).decode(), end="")
    else:
        print((xor(letter, dec2[i])).decode(), end="")

# Flag -> STMCTF{sonunda_8u_flag_dogru_FLAG} 
```










