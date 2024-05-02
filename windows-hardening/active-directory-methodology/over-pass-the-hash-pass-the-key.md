# Over Pass the Hash/Pass the Key

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz? Şirketinizin **HackTricks'te reklamını görmek** ister misiniz? ya da **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin.**
* **Hacking püf noktalarınızı paylaşarak [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**'a PR gönderin.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** saldırısı, geleneksel NTLM protokolünün kısıtlandığı ve Kerberos kimlik doğrulamasının öncelikli olduğu ortamlar için tasarlanmıştır. Bu saldırı, bir kullanıcının NTLM hash'ini veya AES anahtarlarını kullanarak Kerberos biletleri talep ederek ağ içindeki kaynaklara izinsiz erişim sağlar.

Bu saldırıyı gerçekleştirmek için ilk adım, hedeflenen kullanıcının hesabının NTLM hash'ini veya şifresini elde etmeyi içerir. Bu bilgiyi elde ettikten sonra, hesabın bir Ticket Granting Ticket (TGT) alınabilir, bu da saldırganın kullanıcının izinleri olduğu hizmetlere veya makineleri erişmesine olanak tanır.

Süreç aşağıdaki komutlarla başlatılabilir:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
For scenarios necessitating AES256, the `-aesKey [AES key]` option can be utilized. Moreover, the acquired ticket might be employed with various tools, including smbexec.py or wmiexec.py, broadening the scope of the attack.

Encountered issues such as _PyAsn1Error_ or _KDC cannot find the name_ are typically resolved by updating the Impacket library or using the hostname instead of the IP address, ensuring compatibility with the Kerberos KDC.

An alternative command sequence using Rubeus.exe demonstrates another facet of this technique:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Bu yöntem, **Anahtarı Geçir** yaklaşımını yansıtır ve doğrudan kimlik doğrulama amaçları için biletin ele geçirilmesine ve kullanılmasına odaklanır. Bir TGT isteğinin başlatılmasının, varsayılan olarak RC4-HMAC kullanımını belirten `4768: Bir Kerberos kimlik doğrulama bileti (TGT) istendi` olayını tetiklediğine dikkat etmek önemlidir, ancak modern Windows sistemleri AES256'yı tercih eder.

Operasyonel güvenliğe uyum sağlamak ve AES256'yı kullanmak için aşağıdaki komut uygulanabilir:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Referanslar

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **Bir **cybersecurity şirketinde mi çalışıyorsunuz? **Şirketinizi HackTricks'te reklamını görmek ister misiniz**? ya da **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz**? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'ler göndererek [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**. 

</details>
