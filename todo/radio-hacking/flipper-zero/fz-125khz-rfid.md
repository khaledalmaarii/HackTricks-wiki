# FZ - 125kHz RFID

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking hilelerinizi HackTricks** [**ve HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Giriş

125kHz etiketlerin nasıl çalıştığı hakkında daha fazla bilgi için şuna bakın:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Eylemler

Bu tür etiketler hakkında daha fazla bilgi için [**bu giriş yazısını okuyun**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Oku

Kart bilgilerini **okumaya** çalışır. Sonra onları **taklit** edebilir.

{% hint style="warning" %}
Bazı interkomlar, anahtar kopyalamayı önlemeye çalışarak okumadan önce bir yazma komutu gönderir. Yazma başarılı olursa, o etiket sahte olarak kabul edilir. Flipper RFID taklit ettiğinde, okuyucunun orijinalinden ayırt etme şansı olmadığı için böyle bir sorun ortaya çıkmaz.
{% endhint %}

### El ile Ekle

Flipper Zero'da **manuel olarak verileri belirterek sahte kartlar oluşturabilir** ve sonra bunları taklit edebilirsiniz.

#### Kartlardaki Kimlikler

Bazen bir kart aldığınızda, kartın üzerinde görülebilen kimlik (veya bir kısmı) bulabilirsiniz.

* **EM Marin**

Örneğin, bu EM-Marin kartında fiziksel kartta **son 5 baytın son 3'ü açıkça okunabilir**.\
Diğer 2'si karttan okuyamıyorsanız brute-force yöntemiyle bulunabilir.

<figure><img src="../../../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

* **HID**

Aynı durum bu HID kartında da geçerlidir, burada sadece 3 bayttan 2'si kartta yazılı olarak bulunabilir

<figure><img src="../../../.gitbook/assets/image (1014).png" alt=""><figcaption></figcaption></figure>

### Taklit/ Yaz

Bir kartı **kopyaladıktan** veya kimliği **manuel olarak girdikten** sonra Flipper Zero ile bunu **taklit etmek** veya gerçek bir karta **yazmak** mümkündür.

## Referanslar

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking hilelerinizi HackTricks** [**ve HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>
