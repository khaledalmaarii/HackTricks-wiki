# macOS Uygulamaları - İnceleme, hata ayıklama ve Fuzzing

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}


## Statik Analiz

### otool & objdump & nm
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
{% code overflow="wrap" %}
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```
{% endcode %}
```bash
nm -m ./tccd # List of symbols
```
### jtool2 & Disarm

Buradan [**disarm'ı indirin**](https://newosxbook.com/tools/disarm.html).
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
You can [**jtool2'yi buradan indirin**](http://www.newosxbook.com/tools/jtool.html) veya `brew` ile kurabilirsiniz.
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
{% hint style="danger" %}
**jtool, disarm lehine kullanımdan kaldırılmıştır**
{% endhint %}

### Codesign / ldid

{% hint style="success" %}
**`Codesign`** **macOS**'de bulunabilirken, **`ldid`** **iOS**'de bulunabilir
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) , **.pkg** dosyalarını (kurulum dosyaları) incelemek ve yüklemeden önce içeriğini görmek için yararlı bir araçtır.\
Bu kurulum dosyaları, kötü amaçlı yazılım yazarlarının genellikle kötü amaçlı yazılımı **sürdürmek** için kötüye kullandığı `preinstall` ve `postinstall` bash betikleri içerir.

### hdiutil

Bu araç, herhangi bir şeyi çalıştırmadan önce Apple disk görüntülerini (**.dmg**) incelemek için **monte** etmeye olanak tanır:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
It will be mounted in `/Volumes`

### Packed binaries

* Yüksek entropi kontrolü
* String'leri kontrol et (anlaşılır string yoksa, packed)
* MacOS için UPX packer, "\_\_XHDR" adlı bir bölüm oluşturur

## Statik Objective-C analizi

### Metadata

{% hint style="danger" %}
Objective-C ile yazılmış programların **derlendiğinde** [Mach-O ikili dosyalarına](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) **sınıf bildirimlerini** **koruduğunu** unutmayın. Bu tür sınıf bildirimleri **şunları içerir**:
{% endhint %}

* Tanımlanan arayüzler
* Arayüz yöntemleri
* Arayüz örnek değişkenleri
* Tanımlanan protokoller

Bu isimlerin, ikilinin tersine çevrilmesini zorlaştırmak için obfuscate edilebileceğini unutmayın.

### Fonksiyon çağrısı

Bir ikili dosyada Objective-C kullanan bir fonksiyon çağrıldığında, derlenmiş kod o fonksiyonu çağırmak yerine **`objc_msgSend`** çağrısını yapar. Bu, nihai fonksiyonu çağıracaktır:

![](<../../../.gitbook/assets/image (305).png>)

Bu fonksiyonun beklediği parametreler şunlardır:

* İlk parametre (**self**) "mesajı alacak **sınıfın örneğine işaret eden bir işaretçi**"dir. Daha basit bir ifadeyle, bu, metodun çağrıldığı nesnedir. Eğer metod bir sınıf metoduysa, bu sınıf nesnesinin (bütün olarak) bir örneği olacaktır, oysa bir örnek metodu için self, sınıfın bir örneğine işaret edecektir.
* İkinci parametre (**op**), "mesajı işleyen metodun seçicisidir". Yine, daha basit bir ifadeyle, bu sadece **metodun adıdır.**
* Kalan parametreler, metodun gerektirdiği herhangi bir **değerdir** (op).

Bu bilgiyi **`lldb` ile ARM64'te nasıl kolayca alacağınızı** bu sayfada görün:

{% content-ref url="arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](arm64-basic-assembly.md)
{% endcontent-ref %}

x64:

| **Argument**      | **Register**                                                    | **(for) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1st argument**  | **rdi**                                                         | **self: methodun çağrıldığı nesne**                    |
| **2nd argument**  | **rsi**                                                         | **op: metodun adı**                                   |
| **3rd argument**  | **rdx**                                                         | **metodun 1. argümanı**                               |
| **4th argument**  | **rcx**                                                         | **metodun 2. argümanı**                               |
| **5th argument**  | **r8**                                                          | **metodun 3. argümanı**                               |
| **6th argument**  | **r9**                                                          | **metodun 4. argümanı**                               |
| **7th+ argument** | <p><strong>rsp+</strong><br><strong>(stack'te)</strong></p>   | **metodun 5. ve sonrası argümanları**                 |

### Dump ObjectiveC metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump), Objective-C ikili dosyalarını sınıf dökümü yapmak için bir araçtır. Github, dylib'leri belirtmektedir ancak bu, çalıştırılabilir dosyalarla da çalışır.
```bash
./dynadump dump /path/to/bin
```
Yazım zamanı itibarıyla, bu **şu anda en iyi çalışanıdır**.

#### Normal araçlar
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) , ObjetiveC formatında koddaki sınıflar, kategoriler ve protokoller için bildirimler üreten orijinal araçtır.

Eski ve bakımsızdır, bu yüzden muhtemelen düzgün çalışmayacaktır.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) modern ve çok platformlu bir Objective-C sınıf dökümüdür. Mevcut araçlarla karşılaştırıldığında, iCDump Apple ekosisteminden bağımsız olarak çalışabilir ve Python bağlamalarını açığa çıkarır.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Statik Swift analizi

Swift ikili dosyaları ile, Objective-C uyumluluğu olduğundan, bazen [class-dump](https://github.com/nygard/class-dump/) kullanarak bildirimleri çıkartabilirsiniz ama her zaman değil.

**`jtool -l`** veya **`otool -l`** komut satırları ile **`__swift5`** ön eki ile başlayan birkaç bölüm bulmak mümkündür:
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
Bu bölümde saklanan [**bilgiler hakkında daha fazla bilgiye bu blog yazısından ulaşabilirsiniz**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Ayrıca, **Swift ikili dosyaları sembollere sahip olabilir** (örneğin, kütüphanelerin fonksiyonlarının çağrılabilmesi için sembolleri saklaması gerekir). **Semboller genellikle fonksiyon adı ve attr hakkında çirkin bir şekilde bilgi içerir**, bu nedenle çok faydalıdırlar ve orijinal adı alabilen "**demanglers"** vardır:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Dinamik Analiz

{% hint style="warning" %}
Not edin ki, ikili dosyaları hata ayıklamak için, **SIP devre dışı bırakılmalıdır** (`csrutil disable` veya `csrutil enable --without debug`) veya ikili dosyaları geçici bir klasöre kopyalamak ve **imzayı kaldırmak** için `codesign --remove-signature <binary-path>` komutunu kullanmak ya da ikili dosyanın hata ayıklanmasına izin vermek gerekir (bunu [bu script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) ile kullanabilirsiniz).
{% endhint %}

{% hint style="warning" %}
Not edin ki, macOS'ta **sistem ikililerini enstrümante etmek** (örneğin `cloudconfigurationd` gibi) için, **SIP devre dışı bırakılmalıdır** (sadece imzayı kaldırmak işe yaramaz).
{% endhint %}

### API'ler

macOS, süreçler hakkında bilgi veren bazı ilginç API'ler sunar:

* `proc_info`: Her süreç hakkında çok fazla bilgi veren ana API'dir. Diğer süreçlerin bilgilerini almak için root olmanız gerekir, ancak özel yetkilere veya mach portlarına ihtiyacınız yoktur.
* `libsysmon.dylib`: XPC tarafından sunulan işlevler aracılığıyla süreçler hakkında bilgi almayı sağlar, ancak `com.apple.sysmond.client` yetkisine sahip olmak gerekir.

### Stackshot & mikrostackshotlar

**Stackshotting**, süreçlerin durumunu, tüm çalışan iş parçacıklarının çağrı yığınlarını içerecek şekilde yakalamak için kullanılan bir tekniktir. Bu, hata ayıklama, performans analizi ve sistemin belirli bir zamanda davranışını anlamak için özellikle yararlıdır. iOS ve macOS'ta, stackshotting, **`sample`** ve **`spindump`** gibi çeşitli araçlar ve yöntemler kullanılarak gerçekleştirilebilir.

### Sysdiagnose

Bu araç (`/usr/bini/ysdiagnose`), bilgisayarınızdan `ps`, `zprint` gibi onlarca farklı komut çalıştırarak çok fazla bilgi toplar...

**root** olarak çalıştırılmalıdır ve daemon `/usr/libexec/sysdiagnosed` çok ilginç yetkilere sahiptir, bunlar arasında `com.apple.system-task-ports` ve `get-task-allow` bulunmaktadır.

Plist'i `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` konumunda bulunur ve 3 MachServices tanımlar:

* `com.apple.sysdiagnose.CacheDelete`: /var/rmp içindeki eski arşivleri siler
* `com.apple.sysdiagnose.kernel.ipc`: Özel port 23 (kernel)
* `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-C sınıfı aracılığıyla kullanıcı modu arayüzü. Bir sözlükte üç argüman geçirilebilir (`compress`, `display`, `run`)

### Birleşik Günlükler

MacOS, bir uygulama çalıştırırken **ne yaptığını anlamaya** yardımcı olabilecek çok sayıda günlük üretir.

Ayrıca, bazı günlükler, bazı **kullanıcı** veya **bilgisayar** **tanımlanabilir** bilgileri **gizlemek için** `<private>` etiketini içerecektir. Ancak, bu bilgileri açığa çıkarmak için **bir sertifika yüklemek mümkündür**. [**buradan**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log) açıklamaları takip edin.

### Hopper

#### Sol panel

Hopper'ın sol panelinde, ikilinin sembollerini (**Etiketler**), prosedürler ve işlevler listesini (**Proc**) ve dizeleri (**Str**) görebilirsiniz. Bunlar tüm dizeler değildir, ancak Mac-O dosyasının çeşitli bölümlerinde tanımlananlardır (örneğin _cstring veya_ `objc_methname`).

#### Orta panel

Orta panelde **dağıtılmış kodu** görebilirsiniz. Ve bunu **ham** dağıtım, **graf** olarak, **decompile edilmiş** ve **ikili** olarak ilgili simgeye tıklayarak görebilirsiniz:

<figure><img src="../../../.gitbook/assets/image (343).png" alt=""><figcaption></figcaption></figure>

Bir kod nesnesine sağ tıklayarak, o nesneye **referansları/giden referansları** görebilir veya adını değiştirebilirsiniz (bu, decompile edilmiş psödo kodda çalışmaz):

<figure><img src="../../../.gitbook/assets/image (1117).png" alt=""><figcaption></figcaption></figure>

Ayrıca, **orta alanda python komutları yazabilirsiniz**.

#### Sağ panel

Sağ panelde, **navigasyon geçmişi** (bu sayede mevcut duruma nasıl geldiğinizi bilirsiniz), bu işlevi çağıran tüm **işlevleri** ve **bu işlevin çağırdığı** tüm işlevleri görebileceğiniz **çağrı grafiği** ve **yerel değişkenler** bilgileri gibi ilginç bilgiler görebilirsiniz.

### dtrace

Kullanıcılara uygulamalara son derece **düşük seviyede** erişim sağlar ve kullanıcılara **programları izleme** ve hatta yürütme akışlarını değiştirme imkanı sunar. Dtrace, **kernel boyunca yerleştirilen** **prob'lar** kullanır ve sistem çağrılarının başlangıç ve bitiş noktaları gibi yerlerde bulunur.

DTrace, her sistem çağrısı için bir prob oluşturmak üzere **`dtrace_probe_create`** işlevini kullanır. Bu prob'lar, her sistem çağrısının **giriş ve çıkış noktasında** tetiklenebilir. DTrace ile etkileşim, yalnızca root kullanıcı için mevcut olan /dev/dtrace aracılığıyla gerçekleşir.

{% hint style="success" %}
Dtrace'ı SIP korumasını tamamen devre dışı bırakmadan etkinleştirmek için kurtarma modunda şunu çalıştırabilirsiniz: `csrutil enable --without dtrace`

Ayrıca, **derlediğiniz** **`dtrace`** veya **`dtruss`** ikililerini de kullanabilirsiniz.
{% endhint %}

Dtrace'ın mevcut prob'ları şunlarla elde edilebilir:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Probe adı dört bölümden oluşur: sağlayıcı, modül, işlev ve ad (`fbt:mach_kernel:ptrace:entry`). Adın bazı bölümlerini belirtmezseniz, Dtrace o bölümü joker karakter olarak uygular.

DTrace'i probeleri etkinleştirmek ve ateşlendiklerinde hangi eylemlerin gerçekleştirileceğini belirtmek için D dilini kullanmamız gerekecek.

Daha ayrıntılı bir açıklama ve daha fazla örnek için [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html) adresine bakabilirsiniz.

#### Örnekler

Mevcut **DTrace betiklerini** listelemek için `man -k dtrace` komutunu çalıştırın. Örnek: `sudo dtruss -n binary`
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
### kdebug

Bu, bir çekirdek izleme aracıdır. Belgelendirilmiş kodlar **`/usr/share/misc/trace.codes`** içinde bulunabilir.

`latency`, `sc_usage`, `fs_usage` ve `trace` gibi araçlar bunu dahili olarak kullanır.

`kdebug` ile etkileşim kurmak için `sysctl`, `kern.kdebug` ad alanı üzerinden kullanılır ve kullanılacak MIB'ler `bsd/kern/kdebug.c` içinde uygulanan fonksiyonlarla birlikte `sys/sysctl.h` içinde bulunabilir.

Özel bir istemci ile kdebug ile etkileşim kurmak için genellikle bu adımlar izlenir:

* KERN\_KDSETREMOVE ile mevcut ayarları kaldırın
* KERN\_KDSETBUF ve KERN\_KDSETUP ile izlemeyi ayarlayın
* Tampon girişlerinin sayısını almak için KERN\_KDGETBUF kullanın
* KERN\_KDPINDEX ile izlemeyi kendi istemcinizden çıkarın
* KERN\_KDENABLE ile izlemeyi etkinleştirin
* KERN\_KDREADTR çağrısını yaparak tamponu okuyun
* Her bir iş parçacığını süreciyle eşleştirmek için KERN\_KDTHRMAP çağrısını yapın.

Bu bilgiyi almak için Apple aracı **`trace`** veya özel araç [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** kullanılabilir.**

**Kdebug'un aynı anda yalnızca 1 müşteri için mevcut olduğunu unutmayın.** Yani aynı anda yalnızca bir k-debug destekli araç çalıştırılabilir.

### ktrace

`ktrace_*` API'leri, `Kdebug`'ın sarıldığı `libktrace.dylib`'den gelir. Ardından, bir istemci sadece `ktrace_session_create` ve `ktrace_events_[single/class]` çağrısını yaparak belirli kodlar üzerinde geri çağırmaları ayarlayabilir ve ardından `ktrace_start` ile başlatabilir.

Bunu **SIP etkinleştirilmişken** bile kullanabilirsiniz.

İstemci olarak `ktrace` aracını kullanabilirsiniz:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Or `tailspin`.

### kperf

Bu, bir çekirdek düzeyinde profil oluşturmak için kullanılır ve `Kdebug` çağrıları ile oluşturulmuştur.

Temelde, global değişken `kernel_debug_active` kontrol edilir ve ayarlandığında `kperf_kdebug_handler` çağrısı yapılır, `Kdebug` kodu ve çağrılan çekirdek çerçevesinin adresi ile. Eğer `Kdebug` kodu seçilenlerden biri ile eşleşirse, "hareketler" bir bitmap olarak yapılandırılır (seçenekler için `osfmk/kperf/action.h` dosyasına bakın).

Kperf'in ayrıca bir sysctl MIB tablosu vardır: (root olarak) `sysctl kperf`. Bu kodlar `osfmk/kperf/kperfbsd.c` dosyasında bulunabilir.

Ayrıca, Kperf'in bir alt kümesi `kpc` içinde yer alır ve bu, makine performans sayaçları hakkında bilgi sağlar.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor), bir sürecin gerçekleştirdiği süreçle ilgili eylemleri kontrol etmek için çok yararlı bir araçtır (örneğin, bir sürecin hangi yeni süreçleri oluşturduğunu izlemek).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) süreçler arasındaki ilişkileri yazdıran bir araçtır.\
Mac'inizi **`sudo eslogger fork exec rename create > cap.json`** gibi bir komutla izlemelisiniz (bunu başlatan terminal FDA gerektirir). Ardından, bu aracı kullanarak json'u yükleyebilir ve tüm ilişkileri görüntüleyebilirsiniz:

<figure><img src="../../../.gitbook/assets/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor), dosya olaylarını (oluşturma, değişiklikler ve silme gibi) izlemeye olanak tanır ve bu tür olaylar hakkında ayrıntılı bilgi sağlar.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo), Windows kullanıcılarının Microsoft Sysinternal’s _Procmon_'dan tanıyabileceği bir GUI aracıdır. Bu araç, çeşitli olay türlerinin kaydedilmesini başlatıp durdurmaya, bu olayları dosya, süreç, ağ vb. gibi kategorilere göre filtrelemeye ve kaydedilen olayları json formatında kaydetme işlevselliği sunar.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html), Xcode'un Geliştirici araçlarının bir parçasıdır – uygulama performansını izlemek, bellek sızıntılarını tanımlamak ve dosya sistemi etkinliğini takip etmek için kullanılır.

![](<../../../.gitbook/assets/image (1138).png>)

### fs\_usage

Süreçler tarafından gerçekleştirilen eylemleri takip etmeye olanak tanır:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) bir ikili dosyanın kullandığı **kütüphaneleri**, kullandığı **dosyaları** ve **ağ** bağlantılarını görmek için faydalıdır.\
Ayrıca ikili süreçleri **virustotal** ile kontrol eder ve ikili hakkında bilgi gösterir.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

[**bu blog yazısında**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) **SIP** devre dışı bırakılmış olsa bile hata ayıklamayı önlemek için **`PT_DENY_ATTACH`** kullanan bir **çalışan daemon'u hata ayıklama** örneğini bulabilirsiniz.

### lldb

**lldb**, **macOS** ikili **hata ayıklama** için de **facto aracı**dır.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Ev dizininizde aşağıdaki satırı içeren **`.lldbinit`** adında bir dosya oluşturarak lldb kullanırken intel çeşidini ayarlayabilirsiniz:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
lldb içinde, bir işlemi `process save-core` ile dökün
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Komut</strong></td><td><strong>Açıklama</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Bir kesme noktası vurulana veya işlem sona erene kadar devam edecek şekilde yürütmeyi başlatır.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Giriş noktasında durarak yürütmeyi başlatır</td></tr><tr><td><strong>continue (c)</strong></td><td>Hata ayıklanan işlemin yürütülmesine devam eder.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Sonraki talimatı yürütür. Bu komut, işlev çağrılarını atlar.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Sonraki talimatı yürütür. nexti komutunun aksine, bu komut işlev çağrılarına adım atar.</td></tr><tr><td><strong>finish (f)</strong></td><td>Mevcut işlevdeki (“çerçeve”) geri kalan talimatları yürütür, döner ve durur.</td></tr><tr><td><strong>control + c</strong></td><td>Yürütmeyi duraklatır. İşlem run (r) veya continue (c) ile çalıştırıldıysa, bu işlem durmasına neden olur ...şu anda yürütüldüğü yerde.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Herhangi bir main adlı işlev</p><p><code>b &#x3C;binname>`main</code> #Bin'in ana işlevi</p><p><code>b set -n main --shlib &#x3C;lib_name></code> #Belirtilen binin ana işlevi</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Herhangi bir NSFileManager yöntemi</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # O kütüphanedeki tüm işlevlerde kesme noktası</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Kesme noktası listesi</p><p><code>br e/dis &#x3C;num></code> #Kesme noktasını etkinleştir/etkisiz hale getir</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Kesme noktası komutu hakkında yardım al</p><p>help memory write #Belleğe yazma hakkında yardım al</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/bellek adresi></strong></td><td>Belleği null-terminatlı dize olarak görüntüler.</td></tr><tr><td><strong>x/i &#x3C;reg/bellek adresi></strong></td><td>Belleği montaj talimatı olarak görüntüler.</td></tr><tr><td><strong>x/b &#x3C;reg/bellek adresi></strong></td><td>Belleği byte olarak görüntüler.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Bu, parametre ile referans verilen nesneyi yazdırır</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Apple’ın Objective-C API'lerinin veya yöntemlerinin çoğu nesne döndürdüğünden, bunlar “print object” (po) komutu ile görüntülenmelidir. Eğer po anlamlı bir çıktı üretmiyorsa <code>x/b</code> kullanın</p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #O adrese AAAA yaz<br>memory write -f s $rip+0x11f+7 "AAAA" #Adrese AAAA yaz</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Mevcut işlevi disassemble et</p><p>dis -n &#x3C;funcname> #İşlevi disassemble et</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #İşlevi disassemble et<br>dis -c 6 #6 satırı disassemble et<br>dis -c 0x100003764 -e 0x100003768 #Bir eklemden diğerine kadar<br>dis -p -c 4 #Mevcut adreste disassemble etmeye başla</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # x1 reg'deki 3 bileşenli diziyi kontrol et</td></tr><tr><td><strong>image dump sections</strong></td><td>Mevcut işlem belleğinin haritasını yazdırır</td></tr><tr><td><strong>image dump symtab &#x3C;library></strong></td><td><code>image dump symtab CoreNLP</code> #CoreNLP'den tüm sembollerin adresini al</td></tr></tbody></table>

{% hint style="info" %}
**`objc_sendMsg`** fonksiyonu çağrıldığında, **rsi** kaydedicisi **metodun adını** null-terminatlı (“C”) dize olarak tutar. Adı lldb üzerinden yazdırmak için:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anti-Dinamik Analiz

#### VM tespiti

* **`sysctl hw.model`** komutu **host bir MacOS** olduğunda "Mac" döner, ancak bir VM olduğunda farklı bir şey döner.
* **`hw.logicalcpu`** ve **`hw.physicalcpu`** değerleriyle oynayarak bazı kötü amaçlı yazılımlar bir VM olup olmadığını tespit etmeye çalışır.
* Bazı kötü amaçlı yazılımlar, MAC adresine (00:50:56) dayanarak makinenin **VMware** olup olmadığını da **tespit edebilir**.
* Basit bir kod ile **bir işlemin hata ayıklanıp ayıklanmadığını** bulmak da mümkündür:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //işlem hata ayıklanıyor }`
* Ayrıca **`ptrace`** sistem çağrısını **`PT_DENY_ATTACH`** bayrağı ile çağırabilir. Bu, bir hata ayıklayıcının bağlanmasını ve izlenmesini **engeller**.
* **`sysctl`** veya **`ptrace`** fonksiyonunun **içe aktarıldığını** kontrol edebilirsiniz (ancak kötü amaçlı yazılım bunu dinamik olarak içe aktarabilir).
* Bu yazıda belirtildiği gibi, “[Anti-Debug Tekniklerini Aşmak: macOS ptrace varyantları](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Process # exited with **status = 45 (0x0000002d)** mesajı genellikle hata ayıklama hedefinin **PT_DENY_ATTACH** kullandığını gösteren bir işarettir_”

## Core Dumps

Core dump'lar şu durumlarda oluşturulur:

* `kern.coredump` sysctl 1 olarak ayarlanmışsa (varsayılan olarak)
* İşlem suid/sgid değilse veya `kern.sugid_coredump` 1 ise (varsayılan olarak 0)
* `AS_CORE` limiti işlemi izin veriyorsa. Kod dump'larının oluşturulmasını engellemek için `ulimit -c 0` çağrılabilir ve yeniden etkinleştirmek için `ulimit -c unlimited` kullanılabilir.

Bu durumlarda core dump, `kern.corefile` sysctl'e göre oluşturulur ve genellikle `/cores/core/.%P` dizininde saklanır.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **çöken işlemleri analiz eder ve bir çökme raporunu diske kaydeder**. Bir çökme raporu, bir geliştiricinin çökme nedenini teşhis etmesine yardımcı olabilecek bilgileri içerir.\
Kullanıcı başına launchd bağlamında **çalışan uygulamalar ve diğer işlemler** için, ReportCrash bir LaunchAgent olarak çalışır ve çökme raporlarını kullanıcının `~/Library/Logs/DiagnosticReports/` dizinine kaydeder.\
Daimonlar, sistem launchd bağlamında **çalışan diğer işlemler** ve diğer ayrıcalıklı işlemler için, ReportCrash bir LaunchDaemon olarak çalışır ve çökme raporlarını sistemin `/Library/Logs/DiagnosticReports` dizinine kaydeder.

Eğer çökme raporlarının **Apple'a gönderilmesinden endişe ediyorsanız**, bunları devre dışı bırakabilirsiniz. Aksi takdirde, çökme raporları **bir sunucunun nasıl çöktüğünü anlamak için** faydalı olabilir.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Uyku

MacOS'ta fuzzing yaparken Mac'in uykuya dalmasına izin vermemek önemlidir:

* systemsetup -setsleep Never
* pmset, Sistem Tercihleri
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH Bağlantısı Kesilmesi

Eğer bir SSH bağlantısı üzerinden fuzzing yapıyorsanız, oturumun kapanmayacağından emin olmak önemlidir. Bu nedenle sshd\_config dosyasını şu şekilde değiştirin:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Internal Handlers

**Aşağıdaki sayfayı kontrol edin** hangi uygulamanın **belirtilen şemayı veya protokolü işlemekten sorumlu olduğunu bulmak için:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Enumerating Network Processes

Ağ verilerini yöneten süreçleri bulmak ilginçtir:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Or use `netstat` or `lsof`

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
{% endcode %}

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLI araçları için çalışır.

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

macOS GUI araçlarıyla "**sadece çalışır**". Bazı macOS uygulamalarının benzersiz dosya adları, doğru uzantı gibi belirli gereksinimleri olduğunu unutmayın, dosyaları sandbox'tan (`~/Library/Containers/com.apple.Safari/Data`) okumaları gerekir...

Bazı örnekler:

{% code overflow="wrap" %}
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

* [**OS X Olay Yanıtı: Betik Yazma ve Analiz**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**Mac Kötü Amaçlı Yazılım Sanatı: Kötü Amaçlı Yazılımları Analiz Etme Rehberi**](https://taomm.org/)

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Ekip Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Ekip Uzmanı (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.**

</details>
{% endhint %}
