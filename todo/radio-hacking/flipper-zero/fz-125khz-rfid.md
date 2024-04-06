# FZ - 125kHz RFID

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Giriş

125kHz etiketlerin nasıl çalıştığı hakkında daha fazla bilgi için şuna bakın:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## İşlemler

Bu tür etiketler hakkında daha fazla bilgi için [**bu girişi okuyun**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Oku

Kart bilgilerini **okumaya** çalışır. Ardından bunları **taklit** edebilir.

{% hint style="warning" %}
Bazı interkomlar, anahtar kopyalamaya karşı kendilerini korumak için okumadan önce bir yazma komutu göndermeye çalışır. Yazma başarılı olursa, o etiket sahte olarak kabul edilir. Flipper RFID taklit ettiğinde, okuyucunun orijinalinden ayırt etmesi için hiçbir yol olmadığından böyle bir sorun oluşmaz.
{% endhint %}

### El ile Ekle

Flipper Zero'da **manuel olarak veri belirterek sahte kartlar oluşturabilir** ve ardından bunları taklit edebilirsiniz.

#### Kartlardaki Kimlikler

Bazı durumlarda, bir kart aldığınızda kartın görünür bir şekilde ID'si (veya bir kısmı) yazılı olarak bulunabilir.

* **EM Marin**

Örneğin, bu EM-Marin kartında fiziksel kartta **son 5 baytın son 3'ünü açık bir şekilde okumak mümkündür**.\
Diğer 2'si karttan okunamazsa, brute-force yöntemiyle bulunabilir.

<figure><img src="../../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

* **HID**

Aynı durum, bu HID kartında sadece 3 bayttan 2'sinin kartta yazılı olduğu durumda da geçerlidir.

<figure><img src="../../../.gitbook/assets/image (15) (3).png" alt=""><figcaption></figcaption></figure>

### Taklit/Yaz

Bir kartı **kopyaladıktan** veya **manuel olarak** kimliği **girdikten** sonra, Flipper Zero ile bunu **taklit** edebilir veya gerçek bir karta **yazabilirsiniz**.

## Referanslar

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
