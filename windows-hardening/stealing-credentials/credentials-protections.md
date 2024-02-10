# Windows Kimlik Bilgileri Korumaları

## Kimlik Bilgileri Korumaları

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## WDigest

[WDigest](https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396) protokolü, Windows XP ile birlikte tanıtılmış olup, HTTP Protokolü aracılığıyla kimlik doğrulama için tasarlanmıştır ve **Windows XP'den Windows 8.0 ve Windows Server 2003'ten Windows Server 2012'ye kadar varsayılan olarak etkindir**. Bu varsayılan ayar, LSASS'te (Yerel Güvenlik Yetkilendirme Alt Sistemi Hizmeti) **düz metin parola depolamasına** neden olur. Bir saldırgan, Mimikatz'ı kullanarak bu kimlik bilgilerini çıkarabilir. Bunun için şu komutu çalıştırabilir:
```bash
sekurlsa::wdigest
```
Bu özelliği açmak veya kapatmak için, _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ içindeki _**UseLogonCredential**_ ve _**Negotiate**_ kayıt defteri anahtarları "1" olarak ayarlanmalıdır. Bu anahtarlar **mevcut değil veya "0" olarak ayarlanmışsa**, WDigest devre dışı bırakılmıştır:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Koruma

**Windows 8.1** ile başlayarak, Microsoft LSA'nın güvenliğini **güvenilmeyen işlemler tarafından yetkisiz bellek okumalarını veya kod enjeksiyonlarını engellemek** için geliştirdi. Bu geliştirme, `mimikatz.exe sekurlsa:logonpasswords` gibi komutların tipik işleyişini engeller. Bu gelişmiş korumayı **etkinleştirmek** için, _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ içindeki _**RunAsPPL**_ değeri 1 olarak ayarlanmalıdır:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Atlatma

Bu korumayı atlamak mümkündür, Mimikatz sürücüsü mimidrv.sys kullanılarak:

![](../../.gitbook/assets/mimidrv.png)

## Kimlik Bilgisi Koruma

**Kimlik Bilgisi Koruma**, yalnızca **Windows 10 (Enterprise ve Education sürümleri)** için özel bir özelliktir ve **Sanal Güvenli Mod (VSM)** ve **Sanallaştırma Temelli Güvenlik (VBS)** kullanarak makine kimlik bilgilerinin güvenliğini artırır. CPU sanallaştırma uzantılarını kullanarak, önemli işlemleri ana işletim sisteminin erişiminden uzakta korunan bir bellek alanında izole eder. Bu izolasyon, çekirdeğin bile VSM belleğine erişememesini sağlar ve böylece **hash geçirme** gibi saldırılardan kimlik bilgilerini etkili bir şekilde korur. **Yerel Güvenlik Yetkilisi (LSA)**, güvenli bir ortam olarak bu izole ortamda çalışırken, ana işletim sistemindeki **LSASS** süreci yalnızca VSM'nin LSA'sıyla iletişim kurar.

Varsayılan olarak, **Kimlik Bilgisi Koruma** etkin değildir ve bir kuruluş içinde manuel olarak etkinleştirilmesi gerekmektedir. Bu, **Mimikatz** gibi araçlara karşı güvenliği artırmak için kritiktir, çünkü bu araçlar kimlik bilgilerini çıkarmada engellenir. Bununla birlikte, özel **Güvenlik Destek Sağlayıcıları (SSP)** eklenerek kimlik bilgilerinin giriş denemeleri sırasında açık metin olarak ele geçirilmesi yoluyla hala güvenlik açıkları sömürülebilir.

**Kimlik Bilgisi Koruma**'nın etkinleştirme durumunu doğrulamak için **_HKLM\System\CurrentControlSet\Control\LSA_** altında bulunan **_LsaCfgFlags_** kaydı kontrol edilebilir. "**1**" değeri, **UEFI kilidi** ile etkinleştirildiğini, "**2**" değeri kilitsiz etkinleştirildiğini ve "**0**" değeri etkin olmadığını gösterir. Bu kayıt kontrolü, güçlü bir gösterge olsa da, Kimlik Bilgisi Koruma'yı etkinleştirmek için tek adım değildir. Bu özelliği etkinleştirmek için ayrıntılı talimatlar ve bir PowerShell komut dosyası çevrimiçi olarak mevcuttur.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Windows 10'da **Credential Guard**'ı etkinleştirmek ve uyumlu sistemlerde **Windows 11 Enterprise ve Education (sürüm 22H2)** için otomatik etkinleştirmeyi sağlamak için [Microsoft belgelerine](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage) başvurun.

Özel SSP'lerin kimlik bilgisi yakalama için uygulanmasıyla ilgili ayrıntılı bilgiler [bu kılavuzda](../active-directory-methodology/custom-ssp.md) sunulmaktadır.


## RDP RestrictedAdmin Modu

**Windows 8.1 ve Windows Server 2012 R2**, **_RDP için Restricted Admin modunu_** içeren bir dizi yeni güvenlik özelliği tanıttı. Bu mod, **[hash geçirme](https://blog.ahasayen.com/pass-the-hash/)** saldırılarıyla ilişkili riskleri azaltarak güvenliği artırmak için tasarlanmıştır.

Geleneksel olarak, RDP aracılığıyla uzak bir bilgisayara bağlandığınızda kimlik bilgileriniz hedef makinede depolanır. Bu, özellikle yükseltilmiş ayrıcalıklara sahip hesapları kullanırken önemli bir güvenlik riski oluşturur. Ancak, **_Restricted Admin modu_**'nun tanıtılmasıyla bu risk önemli ölçüde azaltılmıştır.

**mstsc.exe /RestrictedAdmin** komutunu kullanarak bir RDP bağlantısı başlattığınızda, uzak bilgisayara kimlik doğrulaması depolanmadan gerçekleştirilir. Bu yaklaşım, kötü amaçlı yazılım enfeksiyonu durumunda veya kötü niyetli bir kullanıcının uzak sunucuya erişim sağlaması durumunda kimlik bilgilerinizin sunucuda depolanmadığı için tehlikeye düşmediğini sağlar.

Önemli bir nokta olarak, **Restricted Admin modunda**, RDP oturumundan ağ kaynaklarına erişim girişimleri kişisel kimlik bilgilerinizi kullanmayacak; bunun yerine **makinenin kimliği** kullanılacaktır.

Bu özellik, uzak masaüstü bağlantılarını güvence altına almak ve güvenlik ihlali durumunda hassas bilgilerin ortaya çıkmasını engellemek için önemli bir adımdır.

![](../../.gitbook/assets/ram.png)

Daha detaylı bilgi için [bu kaynağa](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/) başvurun.


## Önbelleğe Alınmış Kimlik Bilgileri

Windows, **yerel güvenlik otoritesi (LSA)** aracılığıyla **etki alanı kimlik bilgilerini** güvence altına alır ve **Kerberos** ve **NTLM** gibi güvenlik protokolleriyle oturum açma işlemlerini destekler. Windows'un bir özelliği, kullanıcıların şirket ağlarından uzakta sık sık bulunan dizüstü bilgisayar kullanıcıları için bile **etki alanı denetleyicisi çevrimdışı olduğunda bile** son on etki alanı oturum açmasını önbelleğe alabilmesidir.

Önbelleğe alınan oturum açmalarının sayısı belirli bir **kayıt defteri anahtarı veya grup ilkesi** aracılığıyla ayarlanabilir. Bu ayarı görüntülemek veya değiştirmek için aşağıdaki komut kullanılır:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Bu önbelleğe alınmış kimlik bilgilerine erişim sıkı bir şekilde kontrol edilir ve yalnızca **SYSTEM** hesabının bunları görüntülemek için gerekli izinlere sahip olması sağlanır. Bu bilgilere erişmek isteyen yöneticiler, bunu SYSTEM kullanıcı yetkileriyle yapmalıdır. Kimlik bilgileri şurada saklanır: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz**, `lsadump::cache` komutunu kullanarak bu önbelleğe alınmış kimlik bilgilerini çıkarmak için kullanılabilir.

Daha fazla ayrıntı için, orijinal [kaynak](http://juggernaut.wikidot.com/cached-credentials) kapsamlı bilgi sağlar.


## Korunan Kullanıcılar

**Korunan Kullanıcılar grubuna** üyelik, kimlik bilgilerinin çalınması ve kötüye kullanılmasına karşı daha yüksek düzeyde koruma sağlayan birkaç güvenlik geliştirmesini beraberinde getirir:

- **Kimlik Bilgilerinin Delege Edilmesi (CredSSP)**: **Varsayılan kimlik bilgilerinin delege edilmesine izin ver** Grup İlkesi ayarı etkin olsa bile, Korunan Kullanıcıların düz metin kimlik bilgileri önbelleğe alınmaz.
- **Windows Digest**: **Windows 8.1 ve Windows Server 2012 R2**'den itibaren, sistem Korunan Kullanıcıların düz metin kimlik bilgilerini, Windows Digest durumuna bakılmaksızın önbelleğe almaz.
- **NTLM**: Sistem, Korunan Kullanıcıların düz metin kimlik bilgilerini veya NT tek yönlü işlevlerini (NTOWF) önbelleğe almaz.
- **Kerberos**: Korunan Kullanıcılar için Kerberos kimlik doğrulaması, **DES** veya **RC4 anahtarları** üretmez ve düz metin kimlik bilgilerini veya uzun vadeli anahtarları başlangıç Bilet-Veren Bilet (TGT) edinme aşamasından öteye önbelleğe almaz.
- **Çevrimdışı Oturum Açma**: Korunan Kullanıcılar, oturum açma veya kilidi açma sırasında önbelleğe alınmış bir doğrulayıcı oluşturmayacaklarından, çevrimdışı oturum açma bu hesaplar için desteklenmez.

Bu korumalar, **Korunan Kullanıcılar grubu** üyesi olan bir kullanıcının cihaza oturum açtığı anda etkinleştirilir. Bu, kimlik bilgilerinin çeşitli yöntemlerle tehlikeye atılmasına karşı kritik güvenlik önlemlerinin yerinde olduğunu sağlar.

Daha ayrıntılı bilgi için, resmi [belgelendirmeyi](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) inceleyin.

**Tablo** [**belgelerden**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)** alınmıştır.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı yapmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimizi**](https://opensea.io/collection/the-peass-family) görün
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** katkıda bulunun.

</details>
