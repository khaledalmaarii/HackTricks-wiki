# iButton

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** bizi takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Giriş

iButton, **madeni para şeklindeki metal bir kapta** paketlenmiş bir elektronik kimlik anahtarının genel adıdır. Aynı zamanda **Dallas Touch** Bellek veya temas belleği olarak da adlandırılır. Sıklıkla “mıknatıslı” anahtar olarak yanlış bir şekilde anılsa da, içinde **mıknatıslı** hiçbir şey yoktur. Aslında, içinde dijital bir protokol üzerinde çalışan tam teşekküllü bir **mikroçip** gizlidir.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton Nedir? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Genellikle, iButton anahtarın ve okuyucunun fiziksel formunu ifade eder - iki temas noktası olan yuvarlak bir madeni para. Etrafındaki çerçeve için, en yaygın plastik tutucudan delikli olanlara, halkalara, kolyelere vb. birçok varyasyon vardır.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

Anahtar okuyucuya ulaştığında, **temas noktaları birbirine değiyor** ve anahtar **kimliğini iletmek için** güç alıyor. Bazen anahtar **hemen okunmaz** çünkü bir interkomun **temas PSD'si olması gerekenden daha büyüktür**. Bu durumda, anahtarın dış konturları okuyucu ile temas edemez. Eğer durum buysa, anahtarı okuyucunun duvarlarından birinin üzerine basmanız gerekecek.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protokolü** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas anahtarları, 1-wire protokolünü kullanarak veri alışverişi yapar. Veri transferi için yalnızca bir temas noktası (!!) ile her iki yönde, anahtardan köleye ve tersine. 1-wire protokolü, Master-Slave modeline göre çalışır. Bu topolojide, Master her zaman iletişimi başlatır ve Slave onun talimatlarını takip eder.

Anahtar (Slave) interkom (Master) ile temas ettiğinde, anahtarın içindeki çip açılır, interkom tarafından güç sağlanır ve anahtar başlatılır. Ardından interkom anahtar kimliğini talep eder. Bu süreci daha ayrıntılı olarak inceleyeceğiz.

Flipper, hem Master hem de Slave modlarında çalışabilir. Anahtar okuma modunda, Flipper bir okuyucu olarak hareket eder, yani Master olarak çalışır. Anahtar emülasyon modunda ise, Flipper bir anahtar gibi davranır, Slave modundadır.

### Dallas, Cyfral & Metakom anahtarları

Bu anahtarların nasıl çalıştığı hakkında bilgi için [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/) sayfasını kontrol edin.

### Saldırılar

iButton'lar Flipper Zero ile saldırıya uğrayabilir:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Referanslar

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** bizi takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
