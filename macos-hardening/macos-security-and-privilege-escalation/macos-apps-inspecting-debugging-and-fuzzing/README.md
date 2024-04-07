# macOS Uygulamaları - İnceleme, hata ayıklama ve Fuzzing

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Statik Analiz

### otool
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
### objdump

{% code overflow="wrap" %}
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```
### jtool2

Bu araç, **codesign**, **otool** ve **objdump** için bir **yedek** olarak kullanılabilir ve birkaç ek özellik sunar. [**Buradan indirebilirsiniz**](http://www.newosxbook.com/tools/jtool.html) veya `brew` ile kurabilirsiniz.
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
### Codesign / ldid

{% hint style="danger" %}
**`Codesign`**, macOS'ta bulunabilirken **`ldid`**, iOS'ta bulunabilir.
{% endhint %}
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) kurulum dosyaları olan **.pkg** dosyalarını incelemek ve içeriğini kurulum yapmadan önce görmek için faydalı bir araçtır.\
Bu kurulum dosyaları genellikle kötü amaçlı yazılım yazarlarının **kötü amaçlı yazılımı sürdürmek** için genellikle kötüye kullanılan `preinstall` ve `postinstall` bash betiklerine sahiptir.

### hdiutil

Bu araç, Apple disk görüntülerini (**.dmg**) incelemek için dosyaları **bağlamayı** sağlar:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
### Objective-C

#### Metadata

{% hint style="danger" %}
Objective-C ile yazılan programlar, [Mach-O ikili dosyalarına](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) derlendiğinde sınıf bildirimlerini **saklar**. Bu sınıf bildirimleri şunları içerir:

* Sınıfın adı
* Sınıf metodları
* Sınıf örnek değişkenleri
{% endhint %}

Bu bilgilere [**class-dump**](https://github.com/nygard/class-dump) kullanarak erişebilirsiniz:
```bash
class-dump Kindle.app
```
#### Fonksiyon çağrısı

Bir binary dosyasında bir fonksiyon çağrıldığında ve bu binary Objective-C kullandığında, derlenmiş kod o fonksiyonu çağırmak yerine **`objc_msgSend`**'i çağıracaktır. Bu fonksiyon ise son fonksiyonu çağıracaktır:

![](<../../../.gitbook/assets/image (302).png>)

Bu fonksiyonun beklediği parametreler şunlardır:

- İlk parametre (**self**), "mesajı alacak olan sınıf örneğine işaret eden bir işaretçi"dir. Daha basitçe ifade etmek gerekirse, bu, yöntemin çağrıldığı nesnedir. Eğer yöntem bir sınıf yöntemi ise, bu, sınıf nesnesinin bir örneği olacaktır, bir örnek yöntem için ise self, bir nesne olarak sınıfın örneğine işaret edecektir.
- İkinci parametre (**op**), "mesajı işleyen yöntemin seçicisidir". Daha basitçe ifade etmek gerekirse, bu sadece yöntemin **adıdır**.
- Geri kalan parametreler, yöntem tarafından gereken **değerlerdir** (op).

Bu bilgilere **ARM64'te `lldb` ile kolayca nasıl ulaşılacağını** bu sayfada görebilirsiniz:

{% content-ref url="arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](arm64-basic-assembly.md)
{% endcontent-ref %}

x64:

| **Argüman**       | **Register**                                                    | **(için) objc\_msgSend**                              |
| ----------------- | --------------------------------------------------------------- | ---------------------------------------------------- |
| **1. argüman**    | **rdi**                                                         | **self: yöntemin çağrıldığı nesne**                  |
| **2. argüman**    | **rsi**                                                         | **op: yöntemin adı**                                |
| **3. argüman**    | **rdx**                                                         | **yönteme gönderilen 1. argüman**                    |
| **4. argüman**    | **rcx**                                                         | **yönteme gönderilen 2. argüman**                    |
| **5. argüman**    | **r8**                                                          | **yönteme gönderilen 3. argüman**                    |
| **6. argüman**    | **r9**                                                          | **yönteme gönderilen 4. argüman**                    |
| **7. ve sonrası** | <p><strong>rsp+</strong><br><strong>(yığın üzerinde)</strong></p> | **yönteme gönderilen 5. ve sonrası argüman**         |

### Swift

Swift binary dosyalarıyla, Objective-C uyumluluğu olduğundan, bazen [class-dump](https://github.com/nygard/class-dump/) kullanarak deklarasyonları çıkarabilirsiniz ancak her zaman mümkün olmayabilir.

**`jtool -l`** veya **`otool -l`** komut satırları ile **`__swift5`** ön ekini taşıyan birkaç bölüm bulunabilir:
```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
[...]
Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
[...]
```
Bu bölümde depolanan bilgiler hakkında daha fazla bilgiye [bu blog yazısında](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html) ulaşabilirsiniz.

Ayrıca, **Swift ikili dosyalarında semboller olabilir** (örneğin kütüphaneler, işlevlerine çağrı yapılabilmesi için sembollerin depolanması gerekebilir). **Semboller genellikle işlev adı ve özniteliği hakkında bilgi içerir ve karmaşık bir şekilde bulunurlar, bu nedenle çok faydalıdırlar ve orijinal adı alabilen "**demanglers"** bulunmaktadır:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
### Paketlenmiş ikili dosyalar

* Yüksek entropi kontrolü yapın
* Dizeleri kontrol edin (anlaşılabilir bir dize yoksa, paketlenmiş olabilir)
* MacOS için UPX paketleyici bir "\_\_XHDR" adında bir bölüm oluşturur

## Dinamik Analiz

{% hint style="warning" %}
İkili dosyaları hata ayıklamak için **SIP'nin devre dışı bırakılması gerektiğini** unutmayın (`csrutil disable` veya `csrutil enable --without debug`) veya ikili dosyaları geçici bir klasöre kopyalayın ve `codesign --remove-signature <binary-path>` ile imzayı kaldırın veya ikilinin hata ayıklanmasına izin verin (bu betiği kullanabilirsiniz [bu betik](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
MacOS'ta **sistem ikililerini** (örneğin `cloudconfigurationd`) **enstrümanize etmek** için **SIP'nin devre dışı bırakılması gerektiğini** unutmayın (yalnızca imzayı kaldırmak işe yaramaz).
{% endhint %}

### Birleşik Günlükler

MacOS, bir uygulama çalıştırılırken **ne yaptığını anlamaya çalışırken** çok yararlı olabilecek birçok günlük oluşturur.

Ayrıca, bazı günlükler, **kullanıcı** veya **bilgisayar** **tanımlanabilir** bilgileri **gizlemek** için `<private>` etiketini içerecektir. Bununla birlikte, bu bilgileri açıklamak için bir sertifika **yüklenebilir**. [**Buradan**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log) açıklamaları takip edin.

### Hopper

#### Sol panel

Hopper'ın sol panelinde ikilinin sembolleri (**Etiketler**), prosedürlerin ve fonksiyonların listesi (**Proc**) ve dizeler (**Str**) görülebilir. Bunlar, Mac-O dosyasının çeşitli bölümlerinde tanımlanan dizelerdir (_cstring veya_ `objc_methname` gibi).

#### Orta panel

Orta panelde **dizilmiş kodu** görebilirsiniz. Ve **ham** bir şekilde, **grafik** olarak, **derlenmiş** ve **ikili** olarak görebilirsiniz, ilgili simgeye tıklayarak:

<figure><img src="../../../.gitbook/assets/image (340).png" alt=""><figcaption></figcaption></figure>

Bir kod nesnesine sağ tıklayarak **o nesneye referansları** görebilir veya hatta adını değiştirebilirsiniz (bu, derlenmiş yalancı kodda çalışmaz):

<figure><img src="../../../.gitbook/assets/image (1114).png" alt=""><figcaption></figcaption></figure>

Ayrıca, **orta aşağıda python komutları yazabilirsiniz**.

#### Sağ panel

Sağ panelde **gezinme geçmişi** (şu anki duruma nasıl geldiğinizi bilmeniz için) gibi ilginç bilgileri, bu işlevi **çağıran tüm işlevleri** ve bu işlevin **çağırdığı tüm işlevleri** görebileceğiniz **çağrı grafiği**ni ve **yerel değişkenler** bilgilerini görebilirsiniz.

### dtrace

Kullanıcılara uygulamalara son derece **düşük seviyede erişim** sağlar ve kullanıcılara **programları izleme** ve hatta **çalışma akışlarını değiştirme** olanağı sağlar. Dtrace, **çekirdeğin her yerine yerleştirilen** ve sistem çağrılarının başlangıcı ve sonu gibi konumlarda bulunan **probeleri** kullanır.

DTrace, her sistem çağrısı için bir prob oluşturmak için **`dtrace_probe_create`** işlevini kullanır. Bu probeler, her sistem çağrısının **giriş ve çıkış noktasında tetiklenebilir**. DTrace ile etkileşim, yalnızca kök kullanıcılar için kullanılabilen /dev/dtrace üzerinden gerçekleşir.

{% hint style="success" %}
SIP korumasını tamamen devre dışı bırakmadan Dtrace'ı etkinleştirmek için kurtarma modunda şunu çalıştırabilirsiniz: `csrutil enable --without dtrace`

Ayrıca **derlediğiniz** ikilileri **`dtrace`** veya **`dtruss`** ile çalıştırabilirsiniz.
{% endhint %}

Dtrace'ın mevcut probeleri şu şekilde alınabilir:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Sonda bulunan prob adı dört bölümden oluşur: sağlayıcı, modül, işlev ve ad (`fbt:mach_kernel:ptrace:entry`). Adın bazı bölümlerini belirtmezseniz, Dtrace o bölümü joker karakter olarak uygular.

Probları etkinleştirmek ve ateşlendiklerinde ne tür işlemlerin gerçekleştirileceğini belirtmek için D dilini kullanmamız gerekecek.

Daha detaylı bir açıklama ve daha fazla örnek [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html) adresinde bulunabilir.

#### Örnekler

**DTrace komut dosyalarını** listelemek için `man -k dtrace` komutunu çalıştırın. Örnek: `sudo dtruss -n binary`

* Satır içi
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
* betik
```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
;
}
syscall:::return
{
printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```
### dtruss
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### ktrace

Bunu **SIP etkinleştirilmiş bile olsa** kullanabilirsiniz.
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor), bir işlemin gerçekleştirdiği işlemlerle ilgili olarak işlemi denetlemek için çok kullanışlı bir araçtır (örneğin, bir işlemin hangi yeni işlemleri oluşturduğunu izlemek).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/), işlemler arasındaki ilişkileri yazdıran bir araçtır.\
Mac'inizi **`sudo eslogger fork exec rename create > cap.json`** gibi bir komutla izlemeniz gerekmektedir (bu komutu başlatmak için FDA gereklidir). Daha sonra bu araca json dosyasını yükleyerek tüm ilişkileri görebilirsiniz:

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor), dosya etkinliklerini (oluşturma, değiştirme ve silme gibi) izlemeyi sağlayarak bu tür etkinlikler hakkında detaylı bilgi sağlar.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo), Microsoft Sysinternal’s _Procmon_ 'dan Windows kullanıcılarının tanıdığı görünüm ve hisse sahip GUI bir araçtır. Bu araç, çeşitli olay türlerinin kaydedilmesine izin verir ve durdurulmasına olanak tanır, bu olayları dosya, işlem, ağ vb. gibi kategorilere göre filtrelemeye olanak tanır ve kaydedilen olayları json formatında kaydetme işlevselliğini sağlar.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html), Xcode'un Geliştirici Araçları'nın bir parçasıdır - uygulama performansını izlemek, bellek sızıntılarını tanımlamak ve dosya sistemi etkinliğini izlemek için kullanılır.

![](<../../../.gitbook/assets/image (1135).png>)

### fs\_usage

İşlemler tarafından gerçekleştirilen eylemleri takip etmeyi sağlar.
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html), bir ikili dosya tarafından kullanılan kütüphaneleri, kullandığı dosyaları ve ağ bağlantılarını görmek için faydalıdır.\
Ayrıca ikili işlemleri **virustotal**'a karşı kontrol eder ve ikili hakkında bilgi gösterir.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

[**Bu blog yazısında**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html), **`PT_DENY_ATTACH`** kullanan çalışan bir daemon'ı hata ayıklamanın nasıl yapıldığına dair bir örnek bulabilirsiniz, hatta SIP devre dışı bırakılmış olsa bile hata ayıklamayı engellemek için kullanılmıştır.

### lldb

**lldb**, macOS ikili **hata ayıklama** için de facto aracıdır.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Intel lezzetini lldb kullanırken ayarlayabilirsiniz, aşağıdaki satırı içeren **`.lldbinit`** adında bir dosya oluşturarak ev klasörünüzde:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
lldb içinde, bir işlemi `process save-core` ile dump edin.
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Komut</strong></td><td><strong>Açıklama</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Çalıştırmayı başlatır, işlem bir kırılma noktasına ulaşana veya işlem sona erene kadar devam eder.</td></tr><tr><td><strong>continue (c)</strong></td><td>Hata ayıklanan işlemin yürütmesine devam eder.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Sonraki talimatı yürütür. Bu komut fonksiyon çağrılarını atlar.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Sonraki talimatı yürütür. nexti komutunun aksine, bu komut fonksiyon çağrılarına girer.</td></tr><tr><td><strong>finish (f)</strong></td><td>Geçerli fonksiyondaki kalan talimatları yürütür ve duraklar.</td></tr><tr><td><strong>control + c</strong></td><td>Yürütmeyi duraklatır. Eğer işlem çalıştırılmış (r) veya devam ettirilmiş (c) ise, işlemi şu anda nerede yürüttüğünü duraklatır.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Main fonksiyonu çağrıldığında</p><p>b &#x3C;binname>`main #Belirtilen binin ana fonksiyonu</p><p>b set -n main --shlib &#x3C;lib_name> #Belirtilen binin ana fonksiyonu</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Kırılma noktası listesi</p><p>br e/dis &#x3C;num> #Kırılma noktasını etkinleştir/devre dışı bırak</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Kırılma noktası komutunun yardımını al</p><p>help memory write #Belleğe yazma yardımını al</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/bellek adresi></strong></td><td>Belleği null-terminalli bir dize olarak görüntüler.</td></tr><tr><td><strong>x/i &#x3C;reg/bellek adresi></strong></td><td>Belleği derleme talimatı olarak görüntüler.</td></tr><tr><td><strong>x/b &#x3C;reg/bellek adresi></strong></td><td>Belleği bayt olarak görüntüler.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Bu, parametre tarafından referans edilen nesneyi yazdırır</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Apple'ın Objective-C API'lerinin çoğu veya yöntemleri nesneler döndürür, bu nedenle "print object" (po) komutuyla görüntülenmelidir. Eğer po anlamlı bir çıktı üretmiyorsa <code>x/b</code> kullanın</p></td></tr><tr><td><strong>memory</strong></td><td>Belleği oku 0x000....<br>Belleği oku $x0+0xf2a<br>Belleğe yaz 0x100600000 -s 4 0x41414141 #O adrese AAAA yaz<br>Belleğe yaz -f s $rip+0x11f+7 "AAAA" #Adrese AAAA yaz</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Geçerli fonksiyonu derler</p><p>dis -n &#x3C;funcname> #Fonksiyonu derler</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #Fonksiyonu derler<br>dis -c 6 #6 satırı derler<br>dis -c 0x100003764 -e 0x100003768 # Bir adresten diğerine kadar<br>dis -p -c 4 # Geçerli adresin başlangıcında derleme</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # x1 reg içindeki 3 bileşenli diziyi kontrol et</td></tr></tbody></table>

{% hint style="info" %}
**`objc_sendMsg`** fonksiyonu çağrıldığında, **rsi** kaydı **metodun adını** null-terminalli ("C") bir dize olarak tutar. lldb üzerinden adı yazdırmak için:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anti-Dinamik Analiz

#### VM tespiti

* **`sysctl hw.model`** komutu, **ana bilgisayar MacOS** ise "Mac" döndürür, farklı bir şey döndürürse bir VM olduğunu gösterir.
* Bazı kötü amaçlı yazılımlar, bir VM olup olmadığını tespit etmek için **`hw.logicalcpu`** ve **`hw.physicalcpu`** değerleriyle oynar.
* Bazı kötü amaçlı yazılımlar, MAC adresine (00:50:56) dayanarak makinenin **VMware** tabanlı olup olmadığını da **tespit edebilir**.
* Basit bir kodla **bir işlemin hata ayıklanıp ayıklanmadığını** kontrol etmek de mümkündür:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //işlem hata ayıklanıyor }`
* Ayrıca **`ptrace`** sistem çağrısını **`PT_DENY_ATTACH`** bayrağı ile çağırabilir. Bu, bir hata ayıklamanın eklenmesini ve izlenmesini **engeller**.
* **`sysctl`** veya **`ptrace`** fonksiyonunun **ithal edilip edilmediğini** kontrol edebilirsiniz (ancak kötü amaçlı yazılım bunu dinamik olarak da ithal edebilir)
* Bu yazıda belirtildiği gibi, “[Anti-Hata Ayıklama Tekniklerini Yenme: macOS ptrace varyantları](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Process # exited with **status = 45 (0x0000002d)** mesajı genellikle hata ayıklama hedefinin **PT\_DENY\_ATTACH** kullandığının belirtisidir_”
## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash, **çöken işlemleri analiz eder ve bir çökme raporunu diske kaydeder**. Bir çökme raporu, bir çökmenin nedenini teşhis etmeye yardımcı olabilecek bilgiler içerir.\
Kullanıcı başlatma bağlamında çalışan uygulamalar ve diğer işlemler için, ReportCrash bir LaunchAgent olarak çalışır ve çökme raporlarını kullanıcının `~/Library/Logs/DiagnosticReports/` dizinine kaydeder.\
Daemonlar, sistem başlatma bağlamında çalışan diğer işlemler ve diğer ayrıcalıklı işlemler için, ReportCrash bir LaunchDaemon olarak çalışır ve çökme raporlarını sistemin `/Library/Logs/DiagnosticReports` dizinine kaydeder.

Eğer çökme raporlarının **Apple'a gönderilmesinden endişe duyuyorsanız**, bunları devre dışı bırakabilirsiniz. Aksi takdirde, çökme raporları bir sunucunun nasıl çöktüğünü **anlamanıza yardımcı olabilir**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Uyku

MacOS'ta fuzzing yaparken Mac'in uyumasına izin vermemek önemlidir:

* systemsetup -setsleep Never
* pmset, Sistem Tercihleri
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH Bağlantısı Kesme

SSH bağlantısı üzerinden fuzzing yaparken oturumun gün içinde gitmeyeceğinden emin olmak önemlidir. Bu nedenle sshd\_config dosyasını aşağıdaki gibi değiştirin:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Dahili İşleyiciler

Belirli bir şema veya protokolü işlemeden sorumlu olan uygulamanın hangisi olduğunu nasıl bulabileceğinizi öğrenmek için aşağıdaki sayfaya göz atın:

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Ağ İşlemlerini Sıralama

Ağ verilerini yöneten işlemleri bulmak ilginçtir:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Veya `netstat` veya `lsof` kullanın

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLI araçları için çalışır

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

macOS GUI araçları ile "**sadece çalışır"**. Bazı macOS uygulamalarının benzersiz dosya adları, doğru uzantılar gibi belirli gereksinimleri olabilir, dosyaları sandbox'tan okuma ihtiyacı olabilir (`~/Library/Containers/com.apple.Safari/Data`)...

Bazı örnekler:
```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```
{% endcode %}

### Daha Fazla Fuzzing MacOS Bilgisi

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Referanslar

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu görün
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
