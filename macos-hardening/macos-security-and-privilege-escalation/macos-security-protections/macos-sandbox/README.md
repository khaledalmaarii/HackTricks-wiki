# macOS Sandbox

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

## Temel Bilgiler

MacOS Sandbox (başlangıçta Seatbelt olarak adlandırılır) **kum havuzu içinde çalışan uygulamaları** Sandbox profilinde belirtilen **izin verilen eylemlerle sınırlar**. Bu, **uygulamanın yalnızca beklenen kaynaklara erişeceğini** sağlamaya yardımcı olur.

**`com.apple.security.app-sandbox`** yetkisi olan herhangi bir uygulama Sandbox içinde çalıştırılır. **Apple ikili dosyaları** genellikle bir Sandbox içinde çalıştırılır ve **App Store'da yayınlamak için bu yetki zorunludur**. Bu nedenle, çoğu uygulama Sandbox içinde çalıştırılır.

Bir işlemin ne yapabileceğini veya yapamayacağını kontrol etmek için **Sandbox, çekirdek üzerindeki tüm sistem çağrılarında kancalar** bulundurur. Uygulamanın yetkilerine bağlı olarak Sandbox belirli eylemlere izin verecektir.

Sandbox'ın bazı önemli bileşenleri şunlardır:

* **Çekirdek uzantısı** `/System/Library/Extensions/Sandbox.kext`
* **Özel çerçeve** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Kullanıcı alanında çalışan bir **daemon** `/usr/libexec/sandboxd`
* **Konteynerler** `~/Library/Containers`

Konteynerler klasörü içinde, her biri sandbox içinde çalıştırılan uygulama için **bundle kimliğiyle adlandırılmış bir klasör** bulabilirsiniz:
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
Her bir bundle id klasörü içinde, Uygulamanın **plist** ve **Veri dizini** bulunur:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
Unutmayın ki, sembolik bağlantılar Sandbox'tan "kaçmak" ve diğer klasörlere erişmek için olsa bile, Uygulamanın hala bunlara erişmek için **izinlere** sahip olması gerekmektedir. Bu izinler **`.plist`** içinde bulunur.
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
Sandbox uygulaması tarafından oluşturulan/değiştirilen her şey **karantina özelliği**ne sahip olacaktır. Bu, sandbox uygulamasının **`open`** ile bir şeyi çalıştırmaya çalıştığında Gatekeeper'ı tetikleyerek bir sandbox alanını önleyecektir.
{% endhint %}

### Sandbox Profilleri

Sandbox profilleri, o **Sandbox** içinde neyin **izinli/yasaklı** olduğunu belirten yapılandırma dosyalarıdır. Bu, **Sandbox Profil Dili (SBPL)** kullanır ve [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)) programlama dilini kullanır.

İşte bir örnek bulabilirsiniz:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
Daha fazla izin verilen veya reddedilen eylemi kontrol etmek için bu [**araştırmayı**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) kontrol edin.
{% endhint %}

Önemli **sistem hizmetleri** de kendi özel **sandbox**'larında çalışır, örneğin `mdnsresponder` hizmeti. Bu özel **sandbox profillerini** şurada görebilirsiniz:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**
* Diğer sandbox profilleri [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles) adresinde kontrol edilebilir.

**App Store** uygulamaları **`/System/Library/Sandbox/Profiles/application.sb`** profili kullanır. Bu profilde, **`com.apple.security.network.server`** gibi yetkilendirmelerin bir işlemin ağı kullanmasına izin verdiğini kontrol edebilirsiniz.

SIP, /System/Library/Sandbox/rootless.conf dosyasında platform\_profile adlı bir Sandbox profili olarak adlandırılır.

### Sandbox Profili Örnekleri

Bir uygulamayı **belirli bir sandbox profiliyle** başlatmak için şunu kullanabilirsiniz:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% code title="touch.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
{% code title="touch2.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
{% code title="touch3.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Not edin ki **Windows** üzerinde çalışan **Apple tarafından yazılan yazılımların ek güvenlik önlemleri** gibi uygulama sandboxlama gibi ek güvenlik önlemleri yoktur.
{% endhint %}

Bypass örnekleri:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (sandbox dışında `~$` ile başlayan dosyalar yazabiliyorlar).

### MacOS Sandbox Profilleri

macOS, sistem sandbox profillerini iki konumda saklar: **/usr/share/sandbox/** ve **/System/Library/Sandbox/Profiles**.

Ve eğer üçüncü taraf bir uygulama _**com.apple.security.app-sandbox**_ yetkisine sahipse, sistem o işlem için **/System/Library/Sandbox/Profiles/application.sb** profilini uygular.

### **iOS Sandbox Profili**

Varsayılan profil **container** olarak adlandırılır ve SBPL metin temsilini kullanmıyoruz. Bellekte, bu sandbox her izin için Allow/Deny ikili ağacı olarak temsil edilir.

### Hata Ayıklama ve Sandbox'ı Atlatma

macOS'ta, iOS'tan farklı olarak, işlemler çekirdek tarafından baştan itibaren sandbox'a alınmaz, **işlemler kendilerini sandbox'a dahil etmek için aktif olarak seçmelidir**. Bu, macOS'ta bir işlemin sandbox tarafından kısıtlanmadığı anlamına gelir, ta ki aktif olarak içine girmeye karar verene kadar.

İşlemler, `com.apple.security.app-sandbox` yetkisine sahipse, kullanıcı alanından başladıklarında otomatik olarak sandbox'a alınır. Bu işlem hakkında ayrıntılı bir açıklama için şuna bakın:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **PID Yetkilerini Kontrol Etme**

[**Buna göre**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), **`sandbox_check`** (bir `__mac_syscall`), belirli bir PID'deki sandbox tarafından bir işlemin izin verilip verilmediğini kontrol edebilir.

[**sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) aracı, bir PID'nin belirli bir eylemi gerçekleştirebilip gerçekleştiremeyeceğini kontrol edebilir.
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### App Store uygulamalarında özel SBPL

Şirketlerin uygulamalarını varsayılan yerine **özel Sandbox profilleriyle** çalıştırması mümkün olabilir. Bunun için Apple tarafından yetkilendirilmesi gereken **`com.apple.security.temporary-exception.sbpl`** yetkisi kullanılması gerekmektedir.

Bu yetkinliğin tanımını **`/System/Library/Sandbox/Profiles/application.sb:`** dosyasında kontrol etmek mümkündür.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Bu, bu yetkiye sahip bir dizeyi Sandbox profili olarak değerlendirecektir.

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimizden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>
