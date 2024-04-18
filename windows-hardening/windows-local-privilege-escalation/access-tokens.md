# Erişim Jetonları

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz?** **Şirketinizi HackTricks'te reklamını görmek ister misiniz?** ya da **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) **Discord grubuna**](https://discord.gg/hRep4RUj7f) veya **telegram grubuna** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile paylaşın.**

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), **karanlık ağ** destekli bir arama motorudur ve **şirketin veya müşterilerinin** **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini kontrol etmek için ücretsiz** işlevler sunar.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

---

## Erişim Jetonları

**Sisteme giriş yapan her kullanıcı**, o oturum için **güvenlik bilgileri içeren bir erişim jetonuna sahiptir**. Kullanıcı oturum açtığında sistem bir erişim jetonu oluşturur. **Kullanıcı adına yürütülen her işlem**, erişim jetonunun bir kopyasına sahiptir. Jeton, kullanıcıyı, kullanıcının gruplarını ve kullanıcının ayrıcalıklarını tanımlar. Bir jeton ayrıca, mevcut oturumu tanımlayan bir oturum açma SID'si (Güvenlik Tanımlayıcı) içerir.

Bu bilgileri `whoami /all` komutunu çalıştırarak görebilirsiniz.
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
### Erişim belgeleri kullanıcı kimliği taklit

Eğer başka bir kullanıcının geçerli erişim belgelerine sahipseniz, bu kimlik bilgileriyle yeni bir oturum açma oturumu oluşturabilirsiniz:
```
runas /user:domain\username cmd.exe
```
**Erişim belirteci**, aynı zamanda **LSASS** içindeki oturumların bir **referansını** da içerir, bu, işlemin ağdaki bazı nesnelere erişmesi gerekiyorsa faydalıdır.\
Ağ hizmetlerine erişmek için farklı kimlik bilgileri kullanan bir işlem başlatabilirsiniz:
```
runas /user:domain\username /netonly cmd.exe
```
Bu, ağdaki nesnelere erişmek için kullanışlı kimlik bilgileriniz varsa ancak bu kimlik bilgileri yalnızca ağda kullanılacak şekilde geçerli değilse (mevcut ana bilgisayarda mevcut kullanıcı ayrıcalıkları kullanılacaktır).

### Kimlik Bilgilerinin Türleri

Mevcut iki tür kimlik bilgisi vardır:

* **Birincil Kimlik Bilgisi**: Bir işlemin güvenlik kimlik bilgilerinin bir temsili olarak hizmet eder. Birincil kimlik bilgisinin oluşturulması ve işlemlerle ilişkilendirilmesi, ayrıcalık ayrımı ilkesini vurgulayan yükseltilmiş ayrıcalıklar gerektiren eylemlerdir. Genellikle, kimlik doğrulama servisi kimlik bilgisi oluştururken, oturum açma servisi kullanıcının işletim sistemi kabuğuyla ilişkilendirir. İşlemlerin oluşturulduğunda, işlemler ebeveyn işleminin birincil kimlik bilgisini devralırlar.
* **Taklit Kimlik Bilgisi**: Bir sunucu uygulamasının geçici olarak güvenli nesnelere erişmek için istemcinin kimliğini benimsemesini sağlar. Bu mekanizma dört seviyede işler:
  * **Anonim**: Sunucuya kimliği belirsiz bir kullanıcı gibi erişim sağlar.
  * **Tanımlama**: Sunucunun nesnelere erişim için kullanmadan istemcinin kimliğini doğrulamasına izin verir.
  * **Taklit**: Sunucunun istemcinin kimliği altında çalışmasını sağlar.
  * **Delege**: Taklit ile benzerdir ancak sunucunun etkileşimde bulunduğu uzak sistemlere bu kimlik varsayımını genişletme yeteneğini içerir, kimlik bilgisinin korunmasını sağlar.

#### Kimlik Bilgilerini Taklit Etme

Yeterli ayrıcalığınız varsa metasploit'in _**incognito**_ modülünü kullanarak diğer **kimlik bilgilerini listelemek** ve **taklit etmek** kolaydır. Bu, **diğer kullanıcı gibi işlemler gerçekleştirmek** için kullanışlı olabilir. Bu teknikle ayrıca **ayrıcalıkları yükseltebilirsiniz**.

### Kimlik Bilgileri Ayrıcalıkları

**Ayrıcalıkları yükseltmek için kötüye kullanılabilecek kimlik bilgilerini öğrenin:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

[**Tüm olası kimlik bilgisi ayrıcalıklarına ve bazı tanımlamalara bu harici sayfada göz atın**](https://github.com/gtworek/Priv2Admin).

## Referanslar

Bu öğreticilerde kimlik bilgileri hakkında daha fazla bilgi edinin: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) ve [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)


### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **tehlikeye atılıp atılmadığını kontrol etmek için ücretsiz** işlevsellikler sunan **karanlık ağ** destekli bir arama motorudur.

WhiteIntel'in asıl amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme hakkında bilgi edinin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **Bir ** **cybersecurity şirketinde mi çalışıyorsunuz? Şirketinizi HackTricks'te görmek ister misiniz? veya PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi**](https://opensea.io/collection/the-peass-family)'ni keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* **[💬](https://emojipedia.org/speech-balloon/) Discord grubuna** katılın veya [telegram grubuna](https://t.me/peass) veya beni **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve hacktricks-cloud depolarına PR göndererek paylaşın.**

</details>
