# FZ - 125kHz RFID

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Giriş

125kHz etiketlerinin nasıl çalıştığı hakkında daha fazla bilgi için kontrol edin:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Eylemler

Bu tür etiketler hakkında daha fazla bilgi için [**bu girişi okuyun**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Oku

Kart bilgisini **okumaya** çalışır. Sonra bunları **taklit** edebilir.

{% hint style="warning" %}
Bazı interkomların, okumadan önce bir yazma komutu göndererek kendilerini anahtar kopyalamaktan korumaya çalıştığını unutmayın. Yazma başarılı olursa, o etiket sahte olarak kabul edilir. Flipper RFID'yi taklit ettiğinde, okuyucunun bunu orijinalinden ayırt etmesi için bir yol yoktur, bu nedenle böyle bir sorun ortaya çıkmaz.
{% endhint %}

### Manuel Ekle

Flipper Zero'da **verileri belirterek sahte kartlar oluşturabilirsiniz** ve ardından bunu taklit edebilirsiniz.

#### Kartlardaki Kimlikler

Bazen, bir kart aldığınızda, kartta görünür şekilde yazılı olan kimliği (veya bir kısmını) bulacaksınız.

* **EM Marin**

Örneğin, bu EM-Marin kartında fiziksel kartta **son 3'ü 5 baytın açık bir şekilde okunması mümkündür**.\
Diğer 2'si karttan okuyamazsanız brute-force ile bulunabilir.

<figure><img src="../../../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

* **HID**

Bu HID kartında da aynı durum geçerlidir; burada yalnızca 3 bayttan 2'si kartta basılı olarak bulunabilir.

<figure><img src="../../../.gitbook/assets/image (1014).png" alt=""><figcaption></figcaption></figure>

### Taklit/Yaz

Bir kartı **kopyaladıktan** veya kimliği **manuel olarak girdikten** sonra, bunu Flipper Zero ile **taklit** etmek veya gerçek bir karta **yazmak** mümkündür.

## Referanslar

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
