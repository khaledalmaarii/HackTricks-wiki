<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>


# Saldırının Özeti

Bir sunucuyu hayal edin, bu sunucu **bazı verileri imzalıyor** ve bunun için bilinen açık metin verilerine bir **gizli** ekleyip bu veriyi ardından karma işlemine tabi tutuyor. Eğer şunları biliyorsanız:

* **Gizli bilginin uzunluğu** (bu aynı zamanda belirli bir uzunluk aralığından kaba kuvvet saldırısı ile de bulunabilir)
* **Açık metin verisi**
* **Algoritma (ve bu saldırıya karşı savunmasız olması)**
* **Dolgu biliniyor**
* Genellikle varsayılan bir dolgu kullanılır, bu yüzden diğer 3 gereklilik karşılanıyorsa, bu da karşılanır
* Dolgu, gizli+veri uzunluğuna bağlı olarak değişir, bu yüzden gizli bilginin uzunluğuna ihtiyaç vardır

O zaman, bir **saldırganın** **veri ekleyip** ve **önceki veri + eklenen veri** için geçerli bir **imza oluşturması** mümkündür.

## Nasıl?

Temelde savunmasız algoritmalar, öncelikle bir **veri bloğunu karma işlemine tabi tutarak** karma değerlerini oluşturur ve ardından, **önceki** oluşturulan **karma** (durum) **veriden sonraki veri bloğunu ekler ve onu karma işlemine tabi tutar**.

Dolayısıyla, gizli "gizli" ve veri "veri" ise, "gizliveri"nin MD5'i 6036708eba0d11f6ef52ad44e8b74d5b'dir.\
Bir saldırganın "ekle" dizesini eklemek istemesi durumunda:

* 64 "A"nın MD5'ini oluşturur
* Önceden başlatılmış karma işleminin durumunu 6036708eba0d11f6ef52ad44e8b74d5b olarak değiştirir
* "ekle" dizesini ekler
* Karma işlemini tamamlar ve elde edilen karma, "gizli" + "veri" + "dolgu" + "ekle" için **geçerli bir imza olacaktır**

## **Araç**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Referanslar

Bu saldırının iyi açıklandığı yeri [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) adresinde bulabilirsiniz.


<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>
