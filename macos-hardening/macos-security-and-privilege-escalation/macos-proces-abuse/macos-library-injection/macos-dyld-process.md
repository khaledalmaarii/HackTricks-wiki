# macOS Dyld İşlemi

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek destek olun.

</details>

## Temel Bilgiler

Bir Mach-o ikili dosyasının gerçek **giriş noktası**, genellikle `/usr/lib/dyld` olarak tanımlanan dinamik bağlantılıdır ve `LC_LOAD_DYLINKER` içinde tanımlanmıştır.

Bu bağlayıcı, tüm yürütülebilir kütüphaneleri bulmalı, bunları belleğe eşlemeli ve tüm tembel olmayan kütüphaneleri bağlamalıdır. Bu işlem tamamlandıktan sonra ikili dosyanın giriş noktası yürütülecektir.

Tabii ki, **`dyld`** herhangi bir bağımlılığa sahip değildir (sistem çağrıları ve libSystem alıntıları kullanır).

{% hint style="danger" %}
Bu bağlayıcı herhangi bir güvenlik açığı içeriyorsa, yüksek ayrıcalıklı olanlar da dahil olmak üzere herhangi bir ikili dosya yürütülmeden önce yürütüldüğü için **ayrıcalıkları yükseltmek** mümkün olabilir.
{% endhint %}

### Akış

Dyld, **`dyldboostrap::start`** tarafından yüklenecek ve ayrıca **yığın canary** gibi şeyleri de yükleyecektir. Bu işlev, **`apple`** argüman vektöründe bu ve diğer **duyarlı** **değerleri** alacağı için bunu yapacaktır.

**`dyls::_main()`**, dyld'nin giriş noktasıdır ve ilk görevi genellikle **`DYLD_*`** ortam değişkenlerini kısıtlayan `configureProcessRestrictions()` işlevini çalıştırmaktır:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

Daha sonra, önemli sistem kütüphanelerini önceden bağlayan dyld paylaşılan önbelleğini eşler ve ardından ikili dosyanın bağımlı olduğu kütüphaneleri eşler ve ihtiyaç duyulan tüm kütüphaneler yüklenene kadar bu işlemi tekrarlar. Dolayısıyla:

1. `DYLD_INSERT_LIBRARIES` ile eklenen kütüphaneleri yüklemeye başlar (izin verilirse)
2. Ardından paylaşılan önbelleğe sahip olanları
3. Ardından içe aktarılanları
4. &#x20;Daha sonra kütüphaneleri özyinelemeli olarak içe aktarmaya devam eder

Tüm kütüphaneler yüklendikten sonra bu kütüphanelerin **başlatıcıları** çalıştırılır. Bunlar genellikle `LC_ROUTINES[_64]` içinde tanımlanan **`__attribute__((constructor))`** kullanılarak kodlanmıştır (şu anda kullanımdan kaldırılmıştır) veya `S_MOD_INIT_FUNC_POINTERS` bayrağı ile işaretlenmiş bir bölümde işaretçi ile.

Sonlandırıcılar **`__attribute__((destructor))`** ile kodlanır ve genellikle `S_MOD_TERM_FUNC_POINTERS` bayrağı ile işaretlenmiş bir bölümde bulunur (**`__DATA.__mod_term_func`**).

### Yer Tutucular

Tüm macOS ikili dosyaları dinamik olarak bağlanır. Bu nedenle, ikili dosyaların farklı makinelerde ve bağlamlarda doğru kod parçasına atlamasına yardımcı olan bazı yer tutucu bölümleri içerir. İkili dosya yürütüldüğünde, en azından tembel olmayanları çözmesi gereken beyin dyld'dir.

İkili dosyadaki bazı yer tutucu bölümleri:

* **`__TEXT.__[auth_]stubs`**: `__DATA` bölümlerinden işaretçiler
* **`__TEXT.__stub_helper`**: Çağrılacak işlev hakkında bilgi içeren küçük kodlarla dinamik bağlantıyı çağıran küçük kodlar
* **`__DATA.__[auth_]got`**: Global Offset Table (çözüldüğünde ithal edilen işlevlere adresler, yükleme zamanında bağlanır çünkü `S_NON_LAZY_SYMBOL_POINTERS` bayrağı ile işaretlenmiştir)
* **`__DATA.__nl_symbol_ptr`**: Tembel olmayan sembol işaretçileri (yükleme zamanında bağlanır çünkü `S_NON_LAZY_SYMBOL_POINTERS` bayrağı ile işaretlenmiştir)
* **`__DATA.__la_symbol_ptr`**: Tembel sembol işaretçileri (ilk erişimde bağlanır)

{% hint style="warning" %}
"auth\_" önekiyle başlayan işaretçilerin, bunu korumak için bir işlem içi şifreleme anahtarı kullanıldığını unutmayın (PAC). Ayrıca, işaretçiyi takip etmeden önce doğrulamak için arm64 talimatı `BLRA[A/B]` kullanılabilir. Ve RETA\[A/B\], bir RET adresi yerine kullanılabilir.\
Aslında, **`__TEXT.__auth_stubs`** içindeki kod, istenen işlevi doğrulamak için **`braa`** yerine **`bl`** kullanacaktır.

Ayrıca, mevcut dyld sürümlerinin **her şeyi tembel olmayan olarak yüklediğini** unutmayın.
{% endhint %}

### Tembel sembolleri Bulma
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
İlginç ayrıştırma bölümü:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Mümkün olan printf çağrısına yapılan atlamanın **`__TEXT.__stubs`**'a gideceğini görmek mümkündür:
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
Görebileceğiniz gibi **GOT adresine atlıyoruz**, bu durumda tembelden çözülen ve printf fonksiyonunun adresini içerecek olan adres.

Başka durumlarda GOT'a doğrudan atlamak yerine, **`__DATA.__la_symbol_ptr`** adresine atlayabilir, bu da yüklenmeye çalışılan fonksiyonu temsil eden bir değeri yükler, ardından **`__TEXT.__stub_helper`** adresine atlar, bu da **`__DATA.__nl_symbol_ptr`** adresine atlar, bu da **`dyld_stub_binder`** adresini içerir ve bu adres, fonksiyon numarasını ve bir adresi parametre olarak alır.\
Bu son fonksiyon, aranan fonksiyonun adresini bulduktan sonra, gelecekte aramalar yapmamak için bu adresi **`__TEXT.__stub_helper`** içindeki ilgili konuma yazar.

{% hint style="success" %}
Ancak şu anki dyld sürümlerinin her şeyi tembel yükleme olarak yüklediğine dikkat edin.
{% endhint %}

#### Dyld işlem kodları

Son olarak, **`dyld_stub_binder`**'ın belirtilen fonksiyonu bulması ve tekrar aramamak için uygun adrese yazması gerekir. Bunun için dyld içinde işlem kodları (sonlu durum makinesi) kullanır.

## apple\[] argüman vektörü

macOS'ta ana fonksiyon aslında 3 yerine 4 argüman alır. Dördüncüsü apple olarak adlandırılır ve her giriş `anahtar=değer` şeklindedir. Örneğin:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
```markdown
## macOS DYLD Process

### macOS DYLD Process

DYLD is the dynamic linker on macOS. It is responsible for loading dynamic libraries into a process's address space. By abusing the DYLD process, an attacker can inject malicious code into a legitimate process, leading to privilege escalation or other malicious activities.

#### macOS DYLD Process Abuse Techniques

1. **Library Injection**: Attackers can inject malicious dynamic libraries into a process by manipulating the DYLD environment variables or using code injection techniques.

2. **Code Signing Bypass**: Attackers can bypass code signing checks by injecting unsigned dynamic libraries into a process using DYLD.

3. **Process Hollowing**: Attackers can hollow out a legitimate process and replace its code with malicious code loaded via DYLD.

By understanding how the DYLD process works and the potential abuse techniques, defenders can better protect macOS systems from privilege escalation and other security threats.
```
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
Bu değerler ana işlevde ulaştığında, hassas bilgiler zaten bunlardan kaldırılmış olacak veya veri sızıntısı olacaktı.
{% endhint %}

Ana işleme girmeden önce hata ayıklama yaparak tüm bu ilginç değerleri görmek mümkündür:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Geçerli yürütülebilir '/tmp/a' olarak ayarlandı (arm64).
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

Bu, dyld tarafından ihraç edilen ve dyld durumu hakkında bilgi içeren bir yapıdır. [**Kaynak kod**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld\_images.h.auto.html) içinde bulunabilir ve sürüm, dyld\_image\_info dizisine işaretçi, dyld\_image\_notifier'a, işlemin paylaşılan önbellekten ayrılıp ayrılmadığına, libSystem başlatıcısının çağrılıp çağrılmadığına, dyld'nin kendi Mach başlığına işaretçi, dyld sürüm dizesine işaretçi gibi bilgiler içerir...

## dyld çevresel değişkenler

### dyld hata ayıklama

Dyld'ın ne yaptığını anlamaya yardımcı olan ilginç çevresel değişkenler:

* **DYLD\_PRINT\_LIBRARIES**

Yüklenen her kütüphaneyi kontrol edin:
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

Her bir kütüphanenin nasıl yüklendiğini kontrol edin:
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

Her bir kütüphane başlatıcısının çalıştırıldığında yazdırılmasını sağlar:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Diğerleri

* `DYLD_BIND_AT_LAUNCH`: Tembel bağlantılar tembelden olmayanlarla çözülür
* `DYLD_DISABLE_PREFETCH`: \_\_DATA ve \_\_LINKEDIT içeriğinin önceden yüklenmesini devre dışı bırak
* `DYLD_FORCE_FLAT_NAMESPACE`: Tek seviyeli bağlantılar
* `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Çözüm yolları
* `DYLD_INSERT_LIBRARIES`: Belirli bir kütüphaneyi yükle
* `DYLD_PRINT_TO_FILE`: dyld hata ayıklamayı bir dosyaya yaz
* `DYLD_PRINT_APIS`: libdyld API çağrılarını yazdır
* `DYLD_PRINT_APIS_APP`: main tarafından yapılan libdyld API çağrılarını yazdır
* `DYLD_PRINT_BINDINGS`: Bağlandığında sembolleri yazdır
* `DYLD_WEAK_BINDINGS`: Bağlandığında yalnızca zayıf sembolleri yazdır
* `DYLD_PRINT_CODE_SIGNATURES`: Kod imza kayıt işlemlerini yazdır
* `DYLD_PRINT_DOFS`: Yüklenen D-Trace nesne biçimi bölümlerini yazdır
* `DYLD_PRINT_ENV`: dyld tarafından görülen çevreyi yazdır
* `DYLD_PRINT_INTERPOSTING`: Araya girme işlemlerini yazdır
* `DYLD_PRINT_LIBRARIES`: Yüklenen kütüphaneleri yazdır
* `DYLD_PRINT_OPTS`: Yükleme seçeneklerini yazdır
* `DYLD_REBASING`: Sembol yeniden yerleştirme işlemlerini yazdır
* `DYLD_RPATHS`: @rpath genişlemelerini yazdır
* `DYLD_PRINT_SEGMENTS`: Mach-O segmentlerinin eşlemelerini yazdır
* `DYLD_PRINT_STATISTICS`: Zamanlama istatistiklerini yazdır
* `DYLD_PRINT_STATISTICS_DETAILS`: Detaylı zamanlama istatistiklerini yazdır
* `DYLD_PRINT_WARNINGS`: Uyarı mesajlarını yazdır
* `DYLD_SHARED_CACHE_DIR`: Paylaşılan kütüphane önbelleği için kullanılacak yol
* `DYLD_SHARED_REGION`: "kullan", "özel", "kaçın"
* `DYLD_USE_CLOSURES`: Kapanışları etkinleştir

Daha fazlasını şu şekilde bulmak mümkündür:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Veya dyld projesini [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) adresinden indirip klasör içinde çalıştırarak:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## Referanslar

* [**\*OS Internals, Cilt I: Kullanıcı Modu. Jonathan Levin tarafından**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>A'dan Z'ye AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) katılın veya [telegram grubuna](https://t.me/peass) katılın veya bizi Twitter'da** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking hilelerinizi paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
