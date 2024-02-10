<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


# Saldırının Özeti

Bir sunucuyu düşünün, bu sunucu bazı bilinen açık metin verilere bir **gizli** değer ekleyerek ve ardından bu veriyi karma ileme işlemine tabi tutarak **imzalama** işlemi gerçekleştiriyor. Eğer şunları biliyorsanız:

* **Gizli değerin uzunluğu** (bu uzunluk aralığından da brute force yöntemiyle bulunabilir)
* **Açık metin verileri**
* **Algoritma (ve bu saldırıya karşı savunmasız)**
* **Doldurma biliniyor**
* Genellikle varsayılan bir doldurma kullanılır, bu yüzden diğer 3 gereklilik sağlandığında bu da sağlanır
* Doldurma, gizli değer+veri uzunluğuna bağlı olarak değişir, bu yüzden gizli değerin uzunluğuna ihtiyaç vardır

O zaman, bir **saldırganın** **veriye** **ekleme** yapması ve **önceki veri + eklenen veri** için geçerli bir **imza** oluşturması mümkündür.

## Nasıl?

Temel olarak, savunmasız algoritmalar öncelikle bir **veri bloğunu karma** işlemine tabi tutarlar ve ardından **önceden** oluşturulmuş **karma** (durum) **değerinden** başlayarak **bir sonraki veri bloğunu eklerler** ve **karma işlemine tabi tutarlar**.

Öyleyse, gizli değer "gizli" ve veri "veri" ise, "gizliveri"nin MD5'i 6036708eba0d11f6ef52ad44e8b74d5b'dir.\
Bir saldırgan, "ekleme" dizesini eklemek istiyorsa:

* 64 "A"nın MD5'ini oluşturabilir
* Önceden başlatılmış karma işleminin durumunu 6036708eba0d11f6ef52ad44e8b74d5b olarak değiştirebilir
* "ekleme" dizesini ekleyebilir
* Karma işlemini tamamlayabilir ve elde edilen karma, **"gizli" + "veri" + "doldurma" + "ekleme"** için **geçerli bir imza** olacaktır

## **Araç**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Referanslar

Bu saldırıyı iyi bir şekilde açıklayan kaynağı [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) adresinde bulabilirsiniz.


<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
