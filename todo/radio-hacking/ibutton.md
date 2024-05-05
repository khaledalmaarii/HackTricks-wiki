# iButton

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR'lar gönderin.

</details>

## Giriş

iButton, **bir madeni para şeklindeki metal bir kap içine paketlenmiş** bir elektronik kimlik anahtarı için genel bir addır. Ayrıca **Dallas Touch** Memory veya temas belleği olarak da adlandırılır. Sıklıkla "manyetik" bir anahtar olarak yanlışlıkla adlandırılsa da içinde **hiçbir manyetik şey yoktur**. Aslında, dijital bir protokol üzerinde çalışan tam teşekküllü bir **mikroçip** içindedir.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton Nedir? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Genellikle, iButton, anahtarın ve okuyucunun fiziksel formunu ima eder - iki temas noktası olan yuvarlak bir madeni para. Çevresini saran çerçeve için en yaygın plastik tutucudan delikli halkalara, kolyelere vb. birçok varyasyon vardır.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

Anahtar okuyucuya ulaştığında, **temaslar birbirine dokunur** ve anahtar güçlendirilir ve kimliğini **iletmek** için harekete geçer. Bazen anahtar **hemen okunmaz** çünkü **bir apartman dairesinin interkomunun temas PSD'si** olması gerektiğinden daha büyüktür. Bu durumda, anahtarın ve okuyucunun dış konturları temas edemez. Bu durumda, anahtarı okuyucunun duvarlarından biri üzerine bastırmalısınız.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protokolü** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas anahtarları, 1-wire protokolünü kullanarak veri alışverişi yapar. Veri transferi için sadece bir temas noktası (!!) bulunur, hem efendiden köleye hem de ters yönde. 1-wire protokolü, Efendi-Köle modeline göre çalışır. Bu topolojide, Efendi her zaman iletişimi başlatır ve Köle talimatlarını izler.

Anahtar (Köle), interkoma (Efendi) temas ettiğinde, anahtarın içindeki çip açılır, interkom tarafından güçlendirilir ve anahtar başlatılır. Bundan sonra interkom, anahtar kimliğini talep eder. Bundan sonra bu süreci daha detaylı olarak inceleyeceğiz.

Flipper hem Efendi hem de Köle modlarında çalışabilir. Anahtar okuma modunda, Flipper bir okuyucu olarak çalışır yani Efendi olarak çalışır. Ve anahtar emülasyon modunda, flipper bir anahtar gibi davranır, yani Köle modundadır.

### Dallas, Cyfral ve Metakom anahtarları

Bu anahtarların nasıl çalıştığı hakkında bilgi için [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/) sayfasına bakın

### Saldırılar

iButton'lar Flipper Zero ile saldırıya uğrayabilir:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Referanslar

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)
