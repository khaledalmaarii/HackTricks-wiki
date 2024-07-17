<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>


# Saldırının Özeti

Bir sunucuyu hayal edin, bu sunucu bazı **verileri** imzalıyor, bilinen açık metin verilerine bir **gizli** ekleyerek ve ardından bu veriyi karma ile işleyerek. Eğer şunları biliyorsanız:

* **Gizli bilginin uzunluğu** (bu aynı zamanda belirli bir uzunluk aralığından kaba kuvvet saldırısı ile de bulunabilir)
* **Açık metin verisi**
* **Algoritma (ve bu saldırıya karşı savunmasız)**
* **Dolgulama biliniyor**
* Genellikle varsayılan bir dolgulama kullanılır, bu yüzden diğer 3 gereklilik karşılanıyorsa, bu da karşılanır
* Dolgulama, gizli bilgi+veri uzunluğuna bağlı olarak değişir, bu yüzden gizli bilginin uzunluğuna ihtiyaç vardır

O zaman, bir **saldırganın** **veri ekleyebilmesi** ve **önceki veri + eklenen veri** için geçerli bir **imza oluşturabilmesi** mümkündür.

## Nasıl?

Temelde savunmasız algoritmalar, öncelikle bir veri bloğunu karma ile işleyerek karma oluştururlar, ve ardından, **önceki** oluşturulan **karmadan** (durumdan) başlayarak, **bir sonraki veri bloğunu eklerler** ve **karma işlerler**.

Sonra, gizli bilginin "gizli" ve verinin "veri" olduğunu hayal edin, "gizliveri"nin MD5'i 6036708eba0d11f6ef52ad44e8b74d5b.\
Bir saldırgan "ekle" dizesini eklemek isterse:

* 64 "A"nın MD5'ini oluşturur
* Daha önceden başlatılmış karma durumunu 6036708eba0d11f6ef52ad44e8b74d5b olarak değiştirir
* "ekle" dizesini ekler
* Karmayı tamamlar ve sonuçta elde edilen karma, "gizli" + "veri" + "dolgulama" + "ekle" için **geçerli bir tane olacaktır**

## **Araç**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Referanslar

Bu saldırının iyi açıklandığını bulabilirsiniz [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
