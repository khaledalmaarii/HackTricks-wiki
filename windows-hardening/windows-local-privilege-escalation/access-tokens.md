# Erişim Jetonları

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


## Erişim Jetonları

Her **sisteme giriş yapmış kullanıcı**, o oturum için **güvenlik bilgileriyle bir erişim jetonu taşır**. Sistem, kullanıcı giriş yaptığında bir erişim jetonu oluşturur. **Kullanıcı adına yürütülen her işlem**, **erişim jetonunun bir kopyasına** sahiptir. Jeton, kullanıcıyı, kullanıcının gruplarını ve kullanıcının ayrıcalıklarını tanımlar. Bir jeton ayrıca, mevcut oturum açma işlemini tanımlayan bir oturum açma SID'si (Güvenlik Tanımlayıcısı) içerir.

Bu bilgiyi `whoami /all` komutunu çalıştırarak görebilirsiniz.
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
or using _Process Explorer_ from Sysinternals (select process and access"Security" tab):

![](<../../.gitbook/assets/image (772).png>)

### Yerel yönetici

Bir yerel yönetici oturum açtığında, **iki erişim belirteci oluşturulur**: Biri yönetici haklarıyla diğeri normal haklarla. **Varsayılan olarak**, bu kullanıcı bir işlem yürüttüğünde **normal** (yönetici olmayan) **haklara sahip olan** kullanılır. Bu kullanıcı **yönetici olarak** herhangi bir şeyi **çalıştırmaya** çalıştığında ("Yönetici olarak çalıştır" örneğin) **UAC** izin istemek için kullanılacaktır.\
Eğer [**UAC hakkında daha fazla bilgi edinmek istiyorsanız bu sayfayı okuyun**](../authentication-credentials-uac-and-efs/#uac)**.**

### Kimlik bilgileri kullanıcı taklidi

Eğer **herhangi bir başka kullanıcının geçerli kimlik bilgilerine** sahipseniz, bu kimlik bilgileriyle **yeni bir oturum açma** oturumu **oluşturabilirsiniz**:
```
runas /user:domain\username cmd.exe
```
**Erişim belirteci**, **LSASS** içindeki oturum açma oturumlarının da bir **referansına** sahiptir, bu, işlemin ağın bazı nesnelerine erişmesi gerektiğinde faydalıdır.\
Ağ hizmetlerine erişmek için **farklı kimlik bilgileri kullanan** bir işlem başlatabilirsiniz:
```
runas /user:domain\username /netonly cmd.exe
```
Bu, ağdaki nesnelere erişim için geçerli kimlik bilgilerine sahip olduğunuzda faydalıdır, ancak bu kimlik bilgileri mevcut ana bilgisayar içinde geçerli değildir çünkü yalnızca ağda kullanılacaktır (mevcut ana bilgisayarda mevcut kullanıcı ayrıcalıkları kullanılacaktır).

### Token Türleri

İki tür token mevcuttur:

* **Birincil Token**: Bir sürecin güvenlik kimlik bilgilerini temsil eder. Birincil tokenların oluşturulması ve süreçlerle ilişkilendirilmesi, ayrıcalık ayrımını vurgulayan, yükseltilmiş ayrıcalıklar gerektiren eylemlerdir. Genellikle, bir kimlik doğrulama hizmeti token oluşturma işlemini üstlenirken, bir oturum açma hizmeti bunun kullanıcı işletim sistemi kabuğuyla ilişkilendirilmesini yönetir. Süreçlerin, oluşturulduklarında ebeveyn süreçlerinin birincil tokenını miras aldığını belirtmek gerekir.
* **Taklit Token**: Bir sunucu uygulamasının, güvenli nesnelere erişim için istemcinin kimliğini geçici olarak benimsemesini sağlar. Bu mekanizma dört işlem seviyesine ayrılmıştır:
* **Anonim**: Sunucuya, tanımlanamayan bir kullanıcınınki gibi erişim sağlar.
* **Kimlik Doğrulama**: Sunucunun, nesne erişimi için kullanmadan istemcinin kimliğini doğrulamasına olanak tanır.
* **Taklit**: Sunucunun, istemcinin kimliği altında çalışmasını sağlar.
* **Delege**: Taklit ile benzer, ancak sunucunun etkileşimde bulunduğu uzak sistemlere bu kimlik varsayımını genişletme yeteneğini içerir, kimlik bilgilerini korur.

#### Taklit Tokenlar

Metasploit'in _**incognito**_ modülünü kullanarak yeterli ayrıcalıklara sahipseniz, diğer **tokenları** kolayca **listeleyebilir** ve **taklit edebilirsiniz**. Bu, **diğer kullanıcıymış gibi eylemler gerçekleştirmek** için faydalı olabilir. Bu teknikle **ayrıcalıkları yükseltebilirsiniz**.

### Token Ayrıcalıkları

Hangi **token ayrıcalıklarının ayrıcalıkları yükseltmek için kötüye kullanılabileceğini öğrenin:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

[**tüm olası token ayrıcalıkları ve bu dış sayfadaki bazı tanımlar**](https://github.com/gtworek/Priv2Admin) için bir göz atın.

## Referanslar

Tokenlar hakkında daha fazla bilgi edinin: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) ve [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)


{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
