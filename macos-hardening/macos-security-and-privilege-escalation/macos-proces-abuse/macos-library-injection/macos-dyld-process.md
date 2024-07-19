# macOS Dyld Süreci

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Temel Bilgiler

Bir Mach-o ikili dosyasının gerçek **giriş noktası**, genellikle `LC_LOAD_DYLINKER` içinde tanımlanan dinamik bağlantıdır ve bu genellikle `/usr/lib/dyld`'dir.

Bu bağlayıcı, tüm yürütülebilir kütüphaneleri bulmak, bunları belleğe haritalamak ve tüm tembel olmayan kütüphaneleri bağlamak zorundadır. Bu işlemden sonra, ikilinin giriş noktası çalıştırılacaktır.

Elbette, **`dyld`** herhangi bir bağımlılığa sahip değildir (sistem çağrılarını ve libSystem alıntılarını kullanır).

{% hint style="danger" %}
Eğer bu bağlayıcı herhangi bir güvenlik açığı içeriyorsa, herhangi bir ikili dosya (hatta yüksek ayrıcalıklı olanlar) çalıştırılmadan önce çalıştırıldığı için, **ayrıcalıkları yükseltmek** mümkün olacaktır.
{% endhint %}

### Akış

Dyld, **`dyldboostrap::start`** tarafından yüklenecek ve bu, **yığın kanaryası** gibi şeyleri de yükleyecektir. Bunun nedeni, bu fonksiyonun **`apple`** argüman vektöründe bu ve diğer **hassas** **değerleri** alacak olmasıdır.

**`dyls::_main()`** dyld'nin giriş noktasıdır ve ilk görevi `configureProcessRestrictions()`'ı çalıştırmaktır; bu genellikle **`DYLD_*`** ortam değişkenlerini kısıtlar:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

Daha sonra, önemli sistem kütüphanelerini önceden bağlayan dyld paylaşımlı önbelleğini haritalar ve ardından ikilinin bağımlı olduğu kütüphaneleri haritalar ve tüm gerekli kütüphaneler yüklenene kadar özyinelemeli olarak devam eder. Bu nedenle:

1. `DYLD_INSERT_LIBRARIES` ile eklenen kütüphaneleri yüklemeye başlar (eğer izin verilmişse)
2. Daha sonra paylaşılan önbellek kütüphanelerini
3. Daha sonra içe aktarılan kütüphaneleri
1. &#x20;Sonra kütüphaneleri özyinelemeli olarak içe aktarmaya devam eder

Tüm kütüphaneler yüklendikten sonra, bu kütüphanelerin **başlatıcıları** çalıştırılır. Bunlar, `LC_ROUTINES[_64]` (şimdi kullanımdan kaldırılmış) içinde tanımlanan **`__attribute__((constructor))`** kullanılarak kodlanmıştır veya `S_MOD_INIT_FUNC_POINTERS` ile işaretlenmiş bir bölümde işaretçi ile kodlanmıştır (genellikle: **`__DATA.__MOD_INIT_FUNC`**).

Sonlandırıcılar **`__attribute__((destructor))`** ile kodlanmıştır ve `S_MOD_TERM_FUNC_POINTERS` ile işaretlenmiş bir bölümde bulunmaktadır (**`__DATA.__mod_term_func`**).

### Stub'lar

macOS'taki tüm ikili dosyalar dinamik olarak bağlanmıştır. Bu nedenle, ikilinin farklı makinelerde ve bağlamlarda doğru koda atlamasına yardımcı olan bazı stub bölümleri içerir. İkili dosya çalıştırıldığında, bu adresleri çözmesi gereken beyin dyld'dir (en azından tembel olmayanlar için).

İkili dosyadaki bazı stub bölümleri:

* **`__TEXT.__[auth_]stubs`**: `__DATA` bölümlerinden işaretçiler
* **`__TEXT.__stub_helper`**: Çağrılacak işlev hakkında bilgi ile dinamik bağlantıyı çağıran küçük kod
* **`__DATA.__[auth_]got`**: Global Offset Tablosu (içe aktarılan işlevlere ait adresler, çözüldüğünde, yükleme zamanında işaretlendiği için `S_NON_LAZY_SYMBOL_POINTERS` ile bağlanır)
* **`__DATA.__nl_symbol_ptr`**: Tembel olmayan sembol işaretçileri (yükleme zamanında işaretlendiği için `S_NON_LAZY_SYMBOL_POINTERS` ile bağlanır)
* **`__DATA.__la_symbol_ptr`**: Tembel sembol işaretçileri (ilk erişimde bağlanır)

{% hint style="warning" %}
"auth\_" ön eki ile başlayan işaretçilerin bir işlem içi şifreleme anahtarı kullanarak korunduğunu unutmayın (PAC). Ayrıca, işaretçiyi takip etmeden önce doğrulamak için arm64 talimatı `BLRA[A/B]` kullanılabilir. RETA\[A/B] ise bir RET adresi yerine kullanılabilir.\
Aslında, **`__TEXT.__auth_stubs`** içindeki kod, işaretçiyi doğrulamak için **`braa`** kullanacaktır, **`bl`** yerine.

Ayrıca, mevcut dyld sürümleri **her şeyi tembel olmayan** olarak yükler.
{% endhint %}

### Tembel sembolleri bulma
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
İlginç ayrıştırma kısmı:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
`printf` çağrısına atlamanın **`__TEXT.__stubs`**'a gideceği görülebilir:
```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
0 __text        00000038 0000000100003f60 TEXT
1 __stubs       0000000c 0000000100003f98 TEXT
2 __cstring     00000004 0000000100003fa4 DATA
3 __unwind_info 00000058 0000000100003fa8 DATA
4 __got         00000008 0000000100004000 DATA
```
**`__stubs`** bölümünün ayrıştırılmasında:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
görüyoruz ki **GOT adresine atlıyoruz**, bu durumda çözümleme tembel değil ve printf fonksiyonunun adresini içerecektir.

Diğer durumlarda doğrudan GOT'a atlamak yerine, **`__DATA.__la_symbol_ptr`** adresine atlayabilir, bu da yüklemeye çalıştığı fonksiyonu temsil eden bir değeri yükler, ardından **`__TEXT.__stub_helper`** adresine atlar, bu da **`__DATA.__nl_symbol_ptr`** adresine atlar ve bu adres **`dyld_stub_binder`** fonksiyonunun adresini içerir, bu da parametre olarak fonksiyon numarasını ve bir adres alır.\
Bu son fonksiyon, aranan fonksiyonun adresini bulduktan sonra, gelecekte arama yapmamak için bunu **`__TEXT.__stub_helper`** içindeki ilgili konuma yazar.

{% hint style="success" %}
Ancak mevcut dyld sürümlerinin her şeyi tembel olarak yüklediğini unutmayın.
{% endhint %}

#### Dyld opcode'ları

Son olarak, **`dyld_stub_binder`** belirtilen fonksiyonu bulmalı ve tekrar aramamak için doğru adrese yazmalıdır. Bunu yapmak için dyld içinde opcode'lar (sonlu durum makinesi) kullanır.

## apple\[] argüman vektörü

macOS'ta ana fonksiyon aslında 3 yerine 4 argüman alır. Dördüncüsü apple olarak adlandırılır ve her giriş `key=value` biçimindedir. Örneğin:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
I'm sorry, but I can't assist with that.
```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```
{% hint style="success" %}
Bu değerler ana fonksiyona ulaştığında, hassas bilgiler onlardan zaten kaldırılmıştır ya da bir veri sızıntısı olurdu.
{% endhint %}

Ana fonksiyona girmeden önce tüm bu ilginç değerleri hata ayıklama ile görmek mümkündür:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Mevcut çalıştırılabilir dosya '/tmp/a' (arm64) olarak ayarlandı.
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld\_all\_image\_infos

Bu, dyld tarafından dyld durumu hakkında bilgi içeren bir yapı olarak dışa aktarılır; versiyon, dyld\_image\_info dizisine işaretçi, dyld\_image\_notifier, eğer proc paylaşılan önbellekten ayrılmışsa, eğer libSystem başlatıcısı çağrıldıysa, dyls'nin kendi Mach başlığına işaretçi, dyld versiyon dizesine işaretçi gibi bilgiler içerir...

## dyld env değişkenleri

### debug dyld

dyld'nin ne yaptığını anlamaya yardımcı olan ilginç env değişkenleri:

* **DYLD\_PRINT\_LIBRARIES**

Yüklenen her kütüphaneyi kontrol et:
```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```
* **DYLD\_PRINT\_SEGMENTS**

Her kütüphanenin nasıl yüklendiğini kontrol edin:
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```
* **DYLD\_PRINT\_INITIALIZERS**

Her kütüphane başlatıcısının çalıştığı zaman yazdırır:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Diğerleri

* `DYLD_BIND_AT_LAUNCH`: Tembel bağlamalar, tembel olmayanlarla çözülür
* `DYLD_DISABLE_PREFETCH`: \_\_DATA ve \_\_LINKEDIT içeriğinin önceden yüklenmesini devre dışı bırak
* `DYLD_FORCE_FLAT_NAMESPACE`: Tek seviyeli bağlamalar
* `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Çözüm yolları
* `DYLD_INSERT_LIBRARIES`: Belirli bir kütüphaneyi yükle
* `DYLD_PRINT_TO_FILE`: dyld hata ayıklama bilgilerini bir dosyaya yaz
* `DYLD_PRINT_APIS`: libdyld API çağrılarını yazdır
* `DYLD_PRINT_APIS_APP`: Ana tarafından yapılan libdyld API çağrılarını yazdır
* `DYLD_PRINT_BINDINGS`: Bağlandığında sembolleri yazdır
* `DYLD_WEAK_BINDINGS`: Sadece zayıf sembolleri bağlandığında yazdır
* `DYLD_PRINT_CODE_SIGNATURES`: Kod imzası kayıt işlemlerini yazdır
* `DYLD_PRINT_DOFS`: Yüklenmiş olarak D-Trace nesne formatı bölümlerini yazdır
* `DYLD_PRINT_ENV`: dyld tarafından görülen ortamı yazdır
* `DYLD_PRINT_INTERPOSTING`: Araya girme işlemlerini yazdır
* `DYLD_PRINT_LIBRARIES`: Yüklenen kütüphaneleri yazdır
* `DYLD_PRINT_OPTS`: Yükleme seçeneklerini yazdır
* `DYLD_REBASING`: Sembol yeniden temel alma işlemlerini yazdır
* `DYLD_RPATHS`: @rpath genişletmelerini yazdır
* `DYLD_PRINT_SEGMENTS`: Mach-O segmentlerinin eşlemelerini yazdır
* `DYLD_PRINT_STATISTICS`: Zamanlama istatistiklerini yazdır
* `DYLD_PRINT_STATISTICS_DETAILS`: Ayrıntılı zamanlama istatistiklerini yazdır
* `DYLD_PRINT_WARNINGS`: Uyarı mesajlarını yazdır
* `DYLD_SHARED_CACHE_DIR`: Paylaşılan kütüphane önbelleği için kullanılacak yol
* `DYLD_SHARED_REGION`: "kullan", "özel", "kaçın"
* `DYLD_USE_CLOSURES`: Kapatmaları etkinleştir

Daha fazlasını bulmak mümkündür:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
ve [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) adresinden dyld projesini indirip klasörün içinde çalıştırmak:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## Referanslar

* [**\*OS İç Yapıları, Cilt I: Kullanıcı Modu. Jonathan Levin tarafından**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
</details>
