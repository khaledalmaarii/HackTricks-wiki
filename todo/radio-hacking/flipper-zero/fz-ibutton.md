# FZ - iButton

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud github depolarına PR göndererek paylaşın.**

</details>

## Giriş

iButton nedir hakkında daha fazla bilgi için şu adrese bakın:

{% content-ref url="../ibutton.md" %}
[ibutton.md](../ibutton.md)
{% endcontent-ref %}

## Tasarım

Aşağıdaki resmin **mavi** kısmı, **gerçek iButton'u yerleştirmeniz gereken yerdir** böylece Flipper onu **okuyabilir.** **Yeşil** kısım, Flipper zero ile **doğru bir şekilde iButton taklit etmek için okuyucuya dokunmanız gereken yerdir.**

<figure><img src="../../../.gitbook/assets/image (565).png" alt=""><figcaption></figcaption></figure>

## Eylemler

### Oku

Okuma Modunda Flipper, iButton anahtarının dokunmasını bekliyor ve **Dallas, Cyfral ve Metakom** olmak üzere üç tür anahtarı sindirebiliyor. Flipper, anahtarın türünü **kendisi belirleyecek.** Anahtar protokolünün adı, ID numarasının üzerinde ekranda görüntülenecektir.

### Manuel olarak ekle

**Dallas, Cyfral ve Metakom** türünde bir iButton'u **manuel olarak eklemek mümkündür.**

### Taklit et

Kaydedilmiş iButton'ları (okunan veya manuel olarak eklenen) **taklit etmek mümkündür.**

{% hint style="info" %}
Flipper Zero'nun beklenen temaslarını okuyucuya dokunduramazsanız **harici GPIO'yu kullanabilirsiniz:**
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (138).png" alt=""><figcaption></figcaption></figure>

## Referanslar

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud github depolarına PR göndererek paylaşın.**

</details>
