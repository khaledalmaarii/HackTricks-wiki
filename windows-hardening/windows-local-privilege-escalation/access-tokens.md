# Erişim Jetonları

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT koleksiyonumuz**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **göndererek paylaşın**.

</details>

## Erişim Jetonları

Sisteme **giriş yapan her kullanıcı**, o oturum için **güvenlik bilgileri içeren bir erişim jetonuna sahiptir**. Kullanıcı oturum açtığında sistem bir erişim jetonu oluşturur. Kullanıcı adına **yürütülen her işlem**, erişim jetonunun bir kopyasına sahiptir. Jeton, kullanıcıyı, kullanıcının gruplarını ve kullanıcının ayrıcalıklarını tanımlar. Bir jeton ayrıca, geçerli oturumu tanımlayan bir giriş SID'si (Güvenlik Tanımlayıcısı) içerir.

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
veya _Sysinternals'den Process Explorer_ kullanarak (işlemi seçin ve "Güvenlik" sekmesine erişin):

![](<../../.gitbook/assets/image (321).png>)

### Yerel yönetici

Yerel bir yönetici oturum açtığında, **iki erişim belirteci oluşturulur**: Bir tanesi yönetici haklarıyla diğeri normal haklarla. **Varsayılan olarak**, bu kullanıcı bir işlemi yürüttüğünde, **normal** (yönetici olmayan) **haklara sahip olan kullanılır**. Bu kullanıcı herhangi bir şeyi yönetici olarak çalıştırmaya çalıştığında ("Yönetici olarak çalıştır" örneğin) **UAC**, izin istemek için kullanılır.\
[**UAC hakkında daha fazla bilgi edinmek için bu sayfayı okuyun**](../authentication-credentials-uac-and-efs.md#uac)**.**

### Kimlik bilgileri kullanıcı taklit etme

Eğer başka bir kullanıcının **geçerli kimlik bilgilerine sahipseniz**, bu kimlik bilgileriyle bir **yeni oturum açma** oluşturabilirsiniz:
```
runas /user:domain\username cmd.exe
```
**Erişim belirteci**, ayrıca **LSASS** içindeki oturum kayıtlarının bir **referansını** da içerir, bu, işlemin ağ nesnelerine erişmesi gerekiyorsa kullanışlıdır.\
Ağ hizmetlerine erişmek için **farklı kimlik bilgileri kullanan bir işlemi başlatabilirsiniz**. Bunun için:
```
runas /user:domain\username /netonly cmd.exe
```
Bu, ağdaki nesnelere erişmek için kullanışlı kimlik bilgileriniz olsa da, bu kimlik bilgilerinin geçerli olduğu mevcut ana bilgisayarda geçerli olmadığı durumlarda kullanışlıdır (mevcut ana bilgisayarda yalnızca mevcut kullanıcı yetkileri kullanılır).

### Kimlik bilgilerinin türleri

Mevcut iki tür kimlik bilgisi vardır:

* **Birincil Kimlik Bilgisi**: Bir işlemin güvenlik kimlik bilgilerinin bir temsili olarak hizmet eder. Birincil kimlik bilgilerinin oluşturulması ve işlemlerle ilişkilendirilmesi, ayrıcalık ayrımı ilkesini vurgulayan yükseltilmiş ayrıcalıklar gerektiren eylemlerdir. Genellikle, kimlik doğrulama hizmeti kimlik bilgisi oluştururken, oturum açma hizmeti kullanıcının işletim sistemi kabuğuyla ilişkilendirir. İşlem oluşturulduğunda, işlem, ebeveyn işlemin birincil kimlik bilgisini devralır.

* **Taklit Kimlik Bilgisi**: Bir sunucu uygulamasının geçici olarak istemcinin kimliğini benimsemesine olanak tanır ve güvenli nesnelere erişmek için kullanılır. Bu mekanizma, dört işletme seviyesine ayrılmıştır:
- **Anonim**: Kimliği belirlenemeyen bir kullanıcı gibi sunucu erişimi sağlar.
- **Kimlik Doğrulama**: Sunucunun nesne erişimi için kullanmadan istemcinin kimliğini doğrulamasına olanak tanır.
- **Taklit**: Sunucunun istemcinin kimliği altında çalışmasını sağlar.
- **Delege**: Taklit ile benzerdir, ancak sunucunun etkileşimde bulunduğu uzak sistemlere bu kimlik varsayımını genişletme yeteneğini içerir ve kimlik bilgilerinin korunmasını sağlar.

#### Kimlik Bilgilerini Taklit Etme

Metasploit'in _**incognito**_ modülünü kullanarak yeterli ayrıcalıklara sahipseniz, diğer **kimlik bilgilerini listelemek** ve **taklit etmek** kolaydır. Bu, diğer kullanıcı gibi **eylemler gerçekleştirmek** için kullanışlı olabilir. Bu teknikle ayrıca **ayrıcalıkları yükseltebilirsiniz**.

### Kimlik Bilgisi Ayrıcalıkları

Ayrıcalıkları yükseltmek için **hangi kimlik bilgisi ayrıcalıklarının kötüye kullanılabileceğini öğrenin:**

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

[**Tüm olası kimlik bilgisi ayrıcalıklarını ve bu harici sayfada bazı tanımları inceleyin**](https://github.com/gtworek/Priv2Admin).

## Referanslar

Bu öğreticilerde kimlik bilgileri hakkında daha fazla bilgi edinin: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) ve [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **siber güvenlik şirketinde mi çalışıyorsunuz**? **Şirketinizi HackTricks'te reklamını yapmak** veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuz olan özel [**NFT'lerimizi**](https://opensea.io/collection/the-peass-family) keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi paylaşarak** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile PR göndererek** katkıda bulunun.

</details>
