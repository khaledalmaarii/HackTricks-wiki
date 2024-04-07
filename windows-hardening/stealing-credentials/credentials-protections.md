# Windows Kimlik Bilgileri Korumaları

## Kimlik Bilgileri Korumaları

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## WDigest

[WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396) protokolü, Windows XP ile tanıtılmış olup HTTP Protokolü aracılığıyla kimlik doğrulaması için tasarlanmıştır ve **Windows XP'den Windows 8.0'a ve Windows Server 2003'ten Windows Server 2012'ye kadar varsayılan olarak etkindir**. Bu varsayılan ayar, **LSASS'ta (Yerel Güvenlik Otoritesi Alt Sistemi Hizmeti) düz metin şifre depolamasına neden olur**. Bir saldırgan, Mimikatz'ı kullanarak bu kimlik bilgilerini çıkarabilir:
```bash
sekurlsa::wdigest
```
**Bu özelliği kapatmak veya açmak** için _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ içindeki _**UseLogonCredential**_ ve _**Negotiate**_ kayıt anahtarları "1" olarak ayarlanmalıdır. Bu anahtarlar **mevcut değilse veya "0" olarak ayarlanmışsa**, WDigest **devre dışı bırakılmıştır**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Kimlik Bilgileri Koruma

**Windows 8.1** ile başlayarak, Microsoft LSA'nın güvenliğini **geliştirdi ve güvenilmeyen işlemler tarafından yetkisiz bellek okumalarını veya kod enjeksiyonlarını engelledi**. Bu geliştirme, `mimikatz.exe sekurlsa:logonpasswords` gibi komutların tipik işleyişini engeller. Bu **geliştirilmiş korumayı etkinleştirmek** için, _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ içindeki _**RunAsPPL**_ değeri 1 olarak ayarlanmalıdır:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Atlatma

Mimikatz sürücüsü mimidrv.sys kullanılarak bu korumayı atlamak mümkündür:

![](../../.gitbook/assets/mimidrv.png)

## Kimlik Koruma

**Kimlik Koruma**, yalnızca **Windows 10 (Enterprise ve Education sürümlerine)** özgü bir özelliktir ve makine kimlik bilgilerinin güvenliğini **Sanal Güvenli Mod (VSM)** ve **Sanallaştırma Tabanlı Güvenlik (VBS)** kullanarak artırır. CPU sanallaştırma uzantılarını kullanarak ana işletim sisteminin erişim alanının dışında korumalı bir bellek alanında önemli süreçleri izole eder. Bu izolasyon, çekirdeğin bile VSM belleğine erişememesini sağlar ve dolayısıyla **hash geçirme** gibi saldırılardan kimlik bilgilerini etkili bir şekilde korur. **Yerel Güvenlik Otoritesi (LSA)**, bu güvenli ortamda bir güvenlet olarak çalışırken ana işletim sistemindeki **LSASS** süreci yalnızca VSM'nin LSA'sı ile iletişim kurar.

Varsayılan olarak **Kimlik Koruma** etkin değildir ve bir organizasyon içinde manuel olarak etkinleştirilmesi gerekir. Bu, **Mimikatz** gibi araçlara karşı güvenliği artırmak için kritiktir çünkü bu tür araçların kimlik bilgilerini çıkarmadaki yetenekleri engellenir. Bununla birlikte, özel **Güvenlik Destek Sağlayıcıları (SSP)** eklenerek giriş denemeleri sırasında kimlik bilgilerini açık metin olarak yakalamak için hala zafiyetler sömürülebilir.

**Kimlik Koruma**'nın etkinleştirilme durumunu doğrulamak için _**HKLM\System\CurrentControlSet\Control\LSA**_ altındaki _**LsaCfgFlags**_ kayıt anahtarı incelenebilir. "**1**" değeri, **UEFI kilidi** ile etkinleştirildiğini, "**2**" kilitsiz olduğunu ve "**0**" etkin olmadığını gösterir. Bu kayıt defteri kontrolü, güçlü bir gösterge olmasına rağmen, Kimlik Koruma'yı etkinleştirmenin tek adımı değildir. Bu özelliği etkinleştirmek için detaylı rehberlik ve bir PowerShell betiği çevrimiçi olarak mevcuttur.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Windows 10 ve uyumlu sistemlerde **Windows 11 Enterprise ve Education (sürüm 22H2)** için **Credential Guard**'ı etkinleştirmek ve otomatik olarak etkinleştirmek için kapsamlı bir anlayış ve talimatlar için [Microsoft'un belgelerini](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage) ziyaret edin.

Özel SSP'lerin kimlik bilgilerini ele geçirmek için uygulanması hakkında daha fazla ayrıntı [bu kılavuzda](../active-directory-methodology/custom-ssp.md) sağlanmıştır.

## RDP RestrictedAdmin Modu

**Windows 8.1 ve Windows Server 2012 R2**, _**RDP için Restricted Admin modunu**_ içeren birkaç yeni güvenlik özelliği tanıttı. Bu mod, [**hash geçirme**](https://blog.ahasayen.com/pass-the-hash/) saldırılarıyla ilişkili riskleri azaltarak güvenliği artırmayı amaçlamıştır.

Geleneksel olarak, RDP aracılığıyla uzak bir bilgisayara bağlandığınızda kimlik bilgileriniz hedef makinede saklanır. Bu, özellikle yüksek ayrıcalıklı hesapları kullanırken önemli bir güvenlik riski oluşturur. Ancak, _**Restricted Admin modu**_nun tanıtılmasıyla bu risk önemli ölçüde azaltılmıştır.

**mstsc.exe /RestrictedAdmin** komutunu kullanarak bir RDP bağlantısı başlatıldığında, uzak bilgisayara kimlik doğrulaması kimlik bilgilerinizin üzerinde saklanmadan gerçekleştirilir. Bu yaklaşım, kötü amaçlı yazılım bulaşması durumunda veya kötü niyetli bir kullanıcının uzak sunucuya erişim sağlaması durumunda, kimlik bilgilerinizin sunucuda saklanmadığı için tehlikeye düşmediğini sağlar.

**Restricted Admin modu**'nda, RDP oturumundan ağ kaynaklarına erişmeye çalışıldığında kişisel kimlik bilgileriniz kullanılmaz; bunun yerine **makinenin kimliği** kullanılır.

Bu özellik, uzak masaüstü bağlantılarını güvence altına almak ve güvenlik ihlali durumunda hassas bilgilerin açığa çıkmasını engellemek için önemli bir adımı temsil eder.

![](../../.gitbook/assets/RAM.png)

Daha detaylı bilgi için [bu kaynağı](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/) ziyaret edin.

## Önbelleğe Alınmış Kimlik Bilgileri

Windows, **domain kimlik bilgilerini** **Yerel Güvenlik Otoritesi (LSA)** aracılığıyla korur ve **Kerberos** ve **NTLM** gibi güvenlik protokolleri ile oturum açma işlemlerini destekler. Windows'un önemli bir özelliği, **son on domain oturum açma işlemini** önbelleğe alabilmesidir, böylece kullanıcılar **alan denetleyicisi çevrimdışı olduğunda bile** bilgisayarlarına erişebilirler - genellikle şirket ağlarından uzakta olan dizüstü bilgisayar kullanıcıları için bir avantaj.

Önbelleğe alınan oturum açma işlemlerinin sayısı belirli bir **kayıt defteri anahtarı veya grup ilkesi** aracılığıyla ayarlanabilir. Bu ayarı görüntülemek veya değiştirmek için aşağıdaki komut kullanılır:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Erişim bu önbelleğe alınmış kimlik bilgilerine sıkı bir şekilde kontrol edilir, yalnızca **SYSTEM** hesabının bunları görüntülemek için gerekli izinlere sahip olması gerekir. Bu bilgilere erişmek isteyen yöneticiler, bunu SYSTEM kullanıcı ayrıcalıklarıyla yapmalıdır. Kimlik bilgileri şurada saklanır: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** kullanılarak bu önbelleğe alınmış kimlik bilgileri `lsadump::cache` komutu kullanılarak çıkarılabilir.

Daha fazla ayrıntı için, orijinal [kaynak](http://juggernaut.wikidot.com/cached-credentials) kapsamlı bilgi sağlar.

## Korunan Kullanıcılar

**Korunan Kullanıcılar grubu** üyeliği, kullanıcılar için çeşitli güvenlik iyileştirmeleri getirir ve kimlik bilgilerinin çalınmasına ve kötüye kullanılmasına karşı daha yüksek koruma seviyelerini sağlar:

* **Kimlik Bilgisi Delegasyonu (CredSSP)**: **Varsayılan kimlik bilgilerini delegelamaya izin ver** Grup İlkesi ayarı etkinleştirilmiş olsa bile, Korunan Kullanıcıların düz metin kimlik bilgileri önbelleğe alınmaz.
* **Windows Digest**: **Windows 8.1 ve Windows Server 2012 R2**'den itibaren, sistem Korunan Kullanıcıların düz metin kimlik bilgilerini önbelleğe almayacak, Windows Digest durumundan bağımsız olarak.
* **NTLM**: Sistem, Korunan Kullanıcıların düz metin kimlik bilgilerini veya NT tek yönlü fonksiyonları (NTOWF) önbelleğe almayacak.
* **Kerberos**: Korunan Kullanıcılar için, Kerberos kimlik doğrulaması **DES** veya **RC4 anahtarları** oluşturmayacak, düz metin kimlik bilgilerini veya uzun vadeli anahtarları başlangıçta Ticket-Granting Ticket (TGT) ediniminden öteye önbelleğe almayacak.
* **Çevrimdışı Oturum Açma**: Korunan Kullanıcılar, oturum açma veya kilidini açma sırasında önbelleğe alınmış bir doğrulayıcıya sahip olmayacak, bu da bu hesaplar için çevrimdışı oturum açmanın desteklenmediği anlamına gelir.

Bu korumalar, **Korunan Kullanıcılar grubu** üyesi olan bir kullanıcının cihaza oturum açtığı anda etkinleştirilir. Bu, kimlik bilgilerinin çeşitli yöntemlerle tehlikeye atılmasına karşı koruma sağlamak için kritik güvenlik önlemlerinin yerinde olduğundan emin olur.

Daha detaylı bilgi için resmi [belgelendirmeye](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) başvurun.

**Tablo** [**belgelerden**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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
