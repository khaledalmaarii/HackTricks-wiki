# iButton

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan kahraman seviyesine yükseltin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Giriş

iButton, **bir madeni para şeklindeki metal bir kap** içinde paketlenmiş bir elektronik kimlik anahtarı için genel bir isimdir. Ayrıca **Dallas Touch** Memory veya temas belleği olarak da adlandırılır. Sıklıkla yanlış bir şekilde "manyetik" bir anahtar olarak adlandırılır, ancak içinde **hiçbir manyetik** şey yoktur. Aslında, bir dijital protokol üzerinde çalışan tam teşekküllü bir **mikroçip** içine gizlenmiştir.

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### iButton Nedir? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Genellikle, iButton, anahtarın ve okuyucunun fiziksel formunu - iki temas noktalı yuvarlak bir madeni para şeklinde - ima eder. Onu çevreleyen çerçeve için, en yaygın plastik tutucu ile delikten halkalara, kolyelere vb. birçok farklılık vardır.

<figure><img src="../../.gitbook/assets/image (23) (2).png" alt=""><figcaption></figcaption></figure>

Anahtar okuyucuya ulaştığında, **temas noktaları birbirine dokunur** ve anahtar, kimliğini **iletmek** için güçlendirilir. Bazen anahtar **hemen okunmaz**, çünkü bir interkomun **temas PSD'si** olması gerektiğinden daha büyüktür. Bu durumda, anahtarın dış konturları ve okuyucu birbirine dokunamaz. Eğer durum buysa, anahtarı okuyucunun duvarlarından biri üzerine bastırmalısınız.

<figure><img src="../../.gitbook/assets/image (21) (2).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protokolü** <a href="#1-wire-protocol" id="1-wire-protocol"></a>

Dallas anahtarları, 1-wire protokolünü kullanarak veri alışverişi yapar. Veri transferi için sadece bir temas noktası (!!) vardır, hem ana makineden köleye hem de köleden ana makineye. 1-wire protokolü, Ana Makine-Köle modeline göre çalışır. Bu topolojide, Ana Makine her zaman iletişimi başlatır ve Köle talimatlarını takip eder.

Anahtar (Köle), interkom (Ana Makine) ile temas ettiğinde, anahtarın içindeki çip, interkom tarafından beslenerek açılır ve anahtar başlatılır. Bundan sonra interkom, anahtar kimliğini isteyebilir. Şimdi, bu sürece daha detaylı bir şekilde bakacağız.

Flipper hem Ana Makine hem de Köle modlarında çalışabilir. Anahtar okuma modunda, Flipper bir okuyucu olarak çalışır, yani bir Ana Makine gibi çalışır. Anahtar taklit modunda, flipper bir anahtar gibi davranır, yani Köle modundadır.

### Dallas, Cyfral ve Metakom anahtarları

Bu anahtarların nasıl çalıştığı hakkında bilgi için [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/) sayfasını kontrol edin.

### Saldırılar

iButton'lar Flipper Zero ile saldırıya uğrayabilir:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Referanslar

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan kahraman seviyesine yükseltin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
