# Shadow Credentials

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

## Intro <a href="#3f17" id="3f17"></a>

**Check the original post for [all the information about this technique](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

Özetle: Eğer bir kullanıcı/bilgisayarın **msDS-KeyCredentialLink** özelliğine yazabiliyorsanız, o nesnenin **NT hash'ini** alabilirsiniz.

Gönderide, hedefin NTLM hash'ini içeren benzersiz bir **Service Ticket** almak için **public-private key authentication credentials** kurma yöntemi özetlenmiştir. Bu süreç, şifrelenmiş NTLM_SUPPLEMENTAL_CREDENTIAL'in de bulunduğu Privilege Attribute Certificate (PAC) ile ilgilidir ve bu, deşifre edilebilir.

### Requirements

Bu tekniği uygulamak için belirli koşulların sağlanması gerekir:
- En az bir Windows Server 2016 Domain Controller gereklidir.
- Domain Controller'da bir sunucu kimlik doğrulama dijital sertifikası yüklü olmalıdır.
- Active Directory, Windows Server 2016 Fonksiyonel Seviyesinde olmalıdır.
- Hedef nesnenin msDS-KeyCredentialLink niteliğini değiştirmek için yetkilendirilmiş bir hesaba ihtiyaç vardır.

## Abuse

Bilgisayar nesneleri için Key Trust'un kötüye kullanımı, Ticket Granting Ticket (TGT) ve NTLM hash'ini elde etmenin ötesinde adımlar içerir. Seçenekler şunlardır:
1. Hedef ana bilgisayarda ayrıcalıklı kullanıcılar olarak hareket etmek için bir **RC4 silver ticket** oluşturmak.
2. **S4U2Self** ile TGT'yi kullanarak **ayrıcalıklı kullanıcıların** taklit edilmesi, bu da hizmet adını eklemek için Service Ticket'te değişiklikler gerektirir.

Key Trust kötüye kullanımının önemli bir avantajı, saldırgan tarafından üretilen özel anahtarla sınırlı olmasıdır; bu, potansiyel olarak savunmasız hesaplara devredilmesini önler ve kaldırılması zor olabilecek bir bilgisayar hesabı oluşturulmasını gerektirmez.

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Bu saldırı için bir C# arayüzü sağlayan DSInternals'a dayanmaktadır. Whisker ve Python karşılığı **pyWhisker**, Active Directory hesapları üzerinde kontrol sağlamak için `msDS-KeyCredentialLink` niteliğini manipüle etmeyi mümkün kılar. Bu araçlar, hedef nesneden anahtar kimlik bilgilerini ekleme, listeleme, kaldırma ve temizleme gibi çeşitli işlemleri destekler.

**Whisker** işlevleri şunlardır:
- **Add**: Bir anahtar çifti oluşturur ve bir anahtar kimlik bilgisi ekler.
- **List**: Tüm anahtar kimlik bilgisi girişlerini görüntüler.
- **Remove**: Belirtilen bir anahtar kimliğini siler.
- **Clear**: Tüm anahtar kimlik bilgilerini siler, bu da meşru WHfB kullanımını bozabilir.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Whisker işlevselliğini **UNIX tabanlı sistemler** için genişletir, kapsamlı istismar yetenekleri için Impacket ve PyDSInternals'dan yararlanarak KeyCredentials'ı listeleme, ekleme ve kaldırma işlemlerini gerçekleştirir ve bunları JSON formatında içe ve dışa aktarır.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray, **genel kullanıcı gruplarının alan nesneleri üzerinde sahip olabileceği GenericWrite/GenericAll izinlerini istismar etmeyi** amaçlar ve ShadowCredentials'ı geniş bir şekilde uygulamak için kullanılır. Bu, alanın işlevsel seviyesini doğrulamak, alan nesnelerini listelemek ve TGT edinimi ve NT hash ifşası için KeyCredentials eklemeye çalışmak üzere alanına giriş yapmayı içerir. Temizlik seçenekleri ve yinelemeli istismar taktikleri, kullanımını artırır.


## References

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

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
