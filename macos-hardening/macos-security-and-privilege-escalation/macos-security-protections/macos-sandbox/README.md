# macOS Sandbox

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

MacOS Sandbox (ilk adı Seatbelt) **sandbox içinde çalışan uygulamaları** **uygulamanın çalıştığı Sandbox profilinde belirtilen izin verilen eylemlerle** **sınırlar**. Bu, **uygulamanın yalnızca beklenen kaynaklara erişmesini** sağlamaya yardımcı olur.

**`com.apple.security.app-sandbox`** **yetkisine** sahip herhangi bir uygulama sandbox içinde çalıştırılacaktır. **Apple ikili dosyaları** genellikle bir Sandbox içinde çalıştırılır ve **App Store**'da yayınlamak için **bu yetki zorunludur**. Bu nedenle, çoğu uygulama sandbox içinde çalıştırılacaktır.

Bir sürecin ne yapabileceğini veya ne yapamayacağını kontrol etmek için **Sandbox, çekirdek boyunca tüm syscalls'da** **kancalara** sahiptir. Uygulamanın **yetkilerine** bağlı olarak Sandbox belirli eylemleri **izin verir**.

Sandbox'ın bazı önemli bileşenleri şunlardır:

* **çekirdek uzantısı** `/System/Library/Extensions/Sandbox.kext`
* **özel çerçeve** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Kullanıcı alanında çalışan bir **daemon** `/usr/libexec/sandboxd`
* **kapsayıcılar** `~/Library/Containers`

Kapsayıcılar klasörü içinde, **sandbox içinde çalıştırılan her uygulama için bir klasör** bulabilirsiniz ve bu klasörün adı bundle id'sidir:
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
Her bir bundle id klasörünün içinde **plist** ve uygulamanın **Data dizini** bulunabilir:
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
Not edin ki, symlinkler Sandbox'tan "kaçmak" ve diğer klasörlere erişmek için orada olsa da, Uygulamanın yine de onlara erişim için **izinlere sahip olması** gerekir. Bu izinler **`.plist`** dosyasının içindedir.
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
Sandboxed bir uygulama tarafından oluşturulan/değiştirilen her şey **karantina niteliği** alacaktır. Bu, sandbox uygulaması **`open`** ile bir şey çalıştırmaya çalıştığında Gatekeeper'ı tetikleyerek bir sandbox alanını engelleyecektir.
{% endhint %}

### Sandbox Profilleri

Sandbox profilleri, o **Sandbox** içinde neyin **izin verileceğini/yasaklanacağını** belirten yapılandırma dosyalarıdır. **Sandbox Profil Dili (SBPL)** kullanır ve bu dil [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)) programlama dilini temel alır.

Burada bir örnek bulabilirsiniz:
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
Bu [**araştırmaya**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **izin verilebilecek veya reddedilebilecek daha fazla eylemi kontrol etmek için bakın.**
{% endhint %}

Önemli **sistem hizmetleri** kendi özel **sandbox**'larında çalışır, örneğin `mdnsresponder` hizmeti. Bu özel **sandbox profillerini** şu konumda görüntüleyebilirsiniz:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* Diğer sandbox profilleri [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles) adresinde kontrol edilebilir.

**App Store** uygulamaları **`/System/Library/Sandbox/Profiles/application.sb`** **profilini** kullanır. Bu profilde **`com.apple.security.network.server`** gibi yetkilendirmelerin bir sürecin ağı kullanmasına nasıl izin verdiğini kontrol edebilirsiniz.

SIP, /System/Library/Sandbox/rootless.conf içinde platform\_profile olarak adlandırılan bir Sandbox profilidir.

### Sandbox Profil Örnekleri

Belirli bir **sandbox profili** ile bir uygulamayı başlatmak için şunu kullanabilirsiniz:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="touch" %}
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
{% endcode %}

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
Not edin ki **Apple tarafından yazılmış** **yazılım**, **Windows** üzerinde **ek güvenlik önlemlerine** sahip değildir, örneğin uygulama sandboxing.
{% endhint %}

Atlatma örnekleri:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (sandbox dışına `~$` ile başlayan dosyalar yazabiliyorlar).

### MacOS Sandbox Profilleri

macOS, sistem sandbox profillerini iki konumda saklar: **/usr/share/sandbox/** ve **/System/Library/Sandbox/Profiles**.

Ve eğer bir üçüncü taraf uygulama _**com.apple.security.app-sandbox**_ yetkisine sahipse, sistem bu süreç için **/System/Library/Sandbox/Profiles/application.sb** profilini uygular.

### **iOS Sandbox Profili**

Varsayılan profil **container** olarak adlandırılır ve SBPL metin temsiline sahip değiliz. Bellekte, bu sandbox, sandbox'tan her izin için Allow/Deny ikili ağacı olarak temsil edilir.

### Debug & Sandbox'ı Atlatma

macOS'ta, iOS'tan farklı olarak, süreçler başlangıçta çekirdek tarafından sandbox'a alınmaz, **süreçlerin kendilerinin sandbox'a katılmayı seçmesi gerekir**. Bu, macOS'ta bir sürecin, aktif olarak girmeye karar vermediği sürece sandbox tarafından kısıtlanmadığı anlamına gelir.

Süreçler, `com.apple.security.app-sandbox` yetkisine sahip olduklarında kullanıcı alanından otomatik olarak sandbox'a alınır. Bu sürecin detaylı açıklaması için kontrol edin:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **PID Yetkilerini Kontrol Et**

[**Buna göre**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), **`sandbox_check`** (bu bir `__mac_syscall`), belirli bir PID'de **bir işlemin izinli olup olmadığını** kontrol edebilir.

[**sbtool aracı**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c), bir PID'nin belirli bir eylemi gerçekleştirip gerçekleştiremeyeceğini kontrol edebilir:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### App Store uygulamalarında Özel SBPL

Şirketlerin uygulamalarını **özel Sandbox profilleriyle** çalıştırmaları mümkün olabilir (varsayılan olan yerine). Bunun için Apple tarafından yetkilendirilmesi gereken **`com.apple.security.temporary-exception.sbpl`** yetkisini kullanmaları gerekir.

Bu yetkinin tanımını **`/System/Library/Sandbox/Profiles/application.sb:`** dosyasında kontrol etmek mümkündür.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Bu, **bu yetki sonrasındaki dizeyi** bir Sandbox profili olarak **değerlendirecektir**.

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
