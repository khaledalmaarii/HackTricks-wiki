# Erişim Jetonları

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz?** **Şirketinizi HackTricks'te reklamını görmek ister misiniz?** ya da **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) **Discord grubuna**](https://discord.gg/hRep4RUj7f) veya **telegram grubuna** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'ler göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile.**

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) **karanlık ağ** destekli bir arama motorudur ve şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini kontrol etmek için ücretsiz** işlevsellikler sunar.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

***

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
### Yerel yönetici

Bir yerel yönetici oturum açtığında, **iki erişim belirteci oluşturulur**: Bir tanesi yönetici haklarıyla diğeri normal haklarla. **Varsayılan olarak**, bu kullanıcı bir işlemi yürüttüğünde **normal** (yönetici olmayan) **haklara sahip olan kullanılır**. Bu kullanıcı bir şeyi **yönetici olarak yürütmeye çalıştığında** ("Yönetici olarak çalıştır" örneğin) **UAC** izni için sorulacaktır.\
Eğer [**UAC hakkında daha fazla bilgi edinmek istiyorsanız bu sayfayı okuyun**](../authentication-credentials-uac-and-efs/#uac)**.**

### Kimlik kullanıcı taklidi

Eğer **başka bir kullanıcının geçerli kimlik bilgilerine sahipseniz**, bu kimlik bilgileriyle bir **yeni oturum açma oturumu oluşturabilirsiniz**:
```
runas /user:domain\username cmd.exe
```
**Erişim belirteci**, ayrıca **LSASS** içindeki oturumların bir **referansını** da içerir, bu işlem ağdaki bazı nesnelere erişmesi gerekiyorsa faydalıdır.\
Ağ hizmetlerine erişmek için **farklı kimlik bilgilerini kullanan bir işlem başlatabilirsiniz**.
```
runas /user:domain\username /netonly cmd.exe
```
### Token Türleri

İki tür token mevcuttur:

- **Birincil Token**: Bir işlemin güvenlik kimlik bilgilerinin temsili olarak hizmet verir. Birincil token'ın oluşturulması ve işlemlerle ilişkilendirilmesi, ayrıcalık ayrımı ilkesini vurgulayan yükseltilmiş ayrıcalıklar gerektiren eylemlerdir. Genellikle, bir kimlik doğrulama servisi token oluştururken, bir oturum açma servisi kullanıcının işletim sistemi kabuğuyla ilişkilendirir. İşlemlerin oluşturulduğunda, işlem, ebeveyn işleminin birincil token'ını miras alır.
- **Taklit Token**: Bir sunucu uygulamasına geçici olarak güvenli nesnelere erişim için istemcinin kimliğini benimsetme yetkisi verir. Bu mekanizma dört seviyede işlem görür:
  - **Anonim**: Sunucuya kimliği belirsiz bir kullanıcı gibi erişim sağlar.
  - **Tanımlama**: Sunucunun nesne erişimi için kullanmadan istemcinin kimliğini doğrulamasına izin verir.
  - **Taklit**: Sunucunun istemcinin kimliği altında çalışmasını sağlar.
  - **Delege**: Taklit ile benzerdir ancak bu kimlik varsayımını sunucunun etkileşimde bulunduğu uzak sistemlere genişletme yeteneğini içerir, kimlik bilgisinin korunmasını sağlar.

#### Token Taklit Etme

Yeterli ayrıcalıklara sahipseniz metasploit'in _**incognito**_ modülünü kullanarak diğer **token'ları** kolayca **listeleyebilir** ve **taklit edebilirsiniz**. Bu, **diğer kullanıcı gibi işlemler gerçekleştirmek** için faydalı olabilir. Bu teknikle ayrıca **ayrıcalıkları yükseltebilirsiniz**.

### Token Ayrıcalıkları

Ayrıcalıkları yükseltmek için **hangi token ayrıcalıklarının kötüye kullanılabileceğini öğrenin:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

[**Tüm olası token ayrıcalıklarına ve bazı tanımlara bu harici sayfada göz atın**](https://github.com/gtworek/Priv2Admin).

## Referanslar

Bu öğreticilerde token'lar hakkında daha fazla bilgi edinin: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) ve [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **tehlikeye atılıp atılmadığını kontrol etmek için ücretsiz** işlevsellikler sunan **karanlık ağ** destekli bir arama motorudur.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **Bir **[**bilgi güvenliği şirketinde mi çalışıyorsunuz**? Şirketinizi **HackTricks'te reklamını görmek ister misiniz**? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek ister misiniz**? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* **[💬](https://emojipedia.org/speech-balloon/) Discord grubuna** katılın veya [telegram grubuna](https://t.me/peass) veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin**.
* **Hacking püf noktalarınızı göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **üzerinden PR'lar gönderin**.

</details>
