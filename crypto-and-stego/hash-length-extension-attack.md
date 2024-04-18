<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), **dark web** destekli bir arama motorudur ve şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunar.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

---

# Saldırının Özeti

Bir sunucuyu hayal edin ki **bazı bilgileri** **imzalıyor** ve ardından bu verilere bilinen açık metin verilerine bir **gizli** ekleyerek veriyi karmaşık hale getiriyor. Eğer şunları biliyorsanız:

* **Gizli bilginin uzunluğu** (bu aynı zamanda belirli bir uzunluk aralığından kaba kuvvet saldırısıyla da bulunabilir)
* **Açık metin verisi**
* **Algoritma (ve bu saldırıya karşı savunmasızdır)**
* **Dolgu biliniyor**
* Genellikle varsayılan bir tane kullanılır, bu yüzden diğer 3 gereklilik karşılanıyorsa, bu da karşılanır
* Dolgu, gizli+veri uzunluğuna bağlı olarak değişir, bu yüzden gizli bilginin uzunluğuna ihtiyaç vardır

O zaman, bir **saldırganın** **veri ekleyebilmesi** ve **önceki veri + eklenen veri** için geçerli bir **imza oluşturabilmesi** mümkündür.

## Nasıl?

Temelde savunmasız algoritmalar, öncelikle bir **veri bloğunu karmaşık hale getirerek** karma oluşturur ve ardından, **önceki** oluşturulan **karmadan** (durumdan) **sonraki veri bloğunu ekler** ve **karma oluşturur**.

Dolayısıyla, gizli "gizli" ve veri "veri" ise, "gizliveri"nin MD5'i 6036708eba0d11f6ef52ad44e8b74d5b'dir.\
Bir saldırgan "ekleme" dizesini eklemek isterse:

* 64 "A"nın MD5'ini oluşturur
* Önceden başlatılmış karmayı 6036708eba0d11f6ef52ad44e8b74d5b yapar
* "ekleme" dizesini ekler
* Karma işlemini tamamlar ve sonuçta elde edilen karma, "gizli" + "veri" + "dolgu" + "ekleme" için **geçerli** bir tane olacaktır

## **Araç**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Referanslar

Bu saldırının iyi açıklandığını bulabilirsiniz [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), **dark web** destekli bir arama motorudur ve şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunar.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
