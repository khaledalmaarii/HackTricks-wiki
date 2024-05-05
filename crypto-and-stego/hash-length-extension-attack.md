# Hash Uzunluğu Uzatma Saldırısı

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking hilelerinizi göndererek HackTricks ve HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), **karanlık ağ** destekli bir arama motorudur ve şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunar.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

***

## Saldırının Özeti

Bir sunucuyu hayal edin ki **bazı verileri** **imzalıyor** ve bunun için bilinen açık metin verilerine bir **gizli** ekleyip bu veriyi ardından karma işlemine tabi tutuyor. Eğer şunları biliyorsanız:

* **Gizli bilginin uzunluğu** (bu aynı zamanda belirli bir uzunluk aralığından kaba kuvvet saldırısı ile de bulunabilir)
* **Açık metin verisi**
* **Algoritma (ve bu saldırıya karşı savunmasız)**
* **Dolgu biliniyor**
* Genellikle varsayılan bir tane kullanılır, bu yüzden diğer 3 gereklilik karşılanıyorsa, bu da karşılanır
* Dolgu, gizli+veri uzunluğuna bağlı olarak değişir, bu yüzden gizli bilginin uzunluğuna ihtiyaç vardır

O zaman, bir **saldırganın** **veri ekleyip** ve **önceki veri + eklenen veri** için geçerli bir **imza oluşturması** mümkündür.

### Nasıl?

Temelde savunmasız algoritmalar, öncelikle bir veri bloğunu karma işlemine tabi tutarak karma değerlerini oluşturur ve ardından, **önceki** oluşturulan **karma** (durum) **veriden** başlayarak, **bir sonraki veri bloğunu ekler ve onu karmaya tabi tutar**.

Sonra, gizli bilginin "gizli" ve verinin "veri" olduğunu hayal edin, "gizliveri"nin MD5'i 6036708eba0d11f6ef52ad44e8b74d5b'dir.\
Bir saldırgan "ekle" dizesini eklemek isterse:

* 64 "A"nın MD5'ini oluşturur
* Daha önce başlatılan karma durumunu 6036708eba0d11f6ef52ad44e8b74d5b olarak değiştirir
* "ekle" dizesini ekler
* Karmayı bitirir ve sonuçta elde edilen karma, "gizli" + "veri" + "dolgu" + "ekle" için **geçerli** bir tane olacaktır**

### **Araç**

{% embed url="https://github.com/iagox86/hash_extender" %}

### Referanslar

Bu saldırıyı iyi açıklanmış bir şekilde [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) adresinde bulabilirsiniz.

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), **karanlık ağ** destekli bir arama motorudur ve şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunar.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking hilelerinizi göndererek HackTricks ve HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>
