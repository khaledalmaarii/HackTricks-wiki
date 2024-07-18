# FZ - NFC

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Giriş <a href="#id-9wrzi" id="id-9wrzi"></a>

RFID ve NFC hakkında bilgi için aşağıdaki sayfayı kontrol edin:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Desteklenen NFC kartları <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
NFC kartlarının yanı sıra Flipper Zero, birkaç **Mifare** Classic ve Ultralight ile **NTAG** gibi **diğer yüksek frekanslı kart türlerini** de destekler.
{% endhint %}

Yeni NFC kart türleri desteklenen kartlar listesine eklenecektir. Flipper Zero aşağıdaki **NFC kart türü A**'yı (ISO 14443A) destekler:

* ﻿**Banka kartları (EMV)** — yalnızca UID, SAK ve ATQA'yı okur, kaydetmez.
* ﻿**Bilinmeyen kartlar** — (UID, SAK, ATQA) okur ve bir UID'yi taklit eder.

**NFC kart türü B, türü F ve türü V** için Flipper Zero, bir UID'yi kaydetmeden okuyabilir.

### NFC kart türü A <a href="#uvusf" id="uvusf"></a>

#### Banka kartı (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero yalnızca UID, SAK, ATQA ve banka kartlarındaki verileri **kaydetmeden** okuyabilir.

Banka kartı okuma ekranıBanka kartları için Flipper Zero yalnızca verileri **kaydetmeden ve taklit etmeden** okuyabilir.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Bilinmeyen kartlar <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zero **NFC kartının türünü belirleyemediğinde**, yalnızca **UID, SAK ve ATQA** okunabilir ve **kaydedilebilir**.

Bilinmeyen kart okuma ekranıBilinmeyen NFC kartları için Flipper Zero yalnızca bir UID'yi taklit edebilir.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC kart türleri B, F ve V <a href="#wyg51" id="wyg51"></a>

**NFC kart türleri B, F ve V** için Flipper Zero yalnızca **bir UID'yi okuyabilir ve görüntüleyebilir** kaydetmeden.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Eylemler

NFC hakkında bir giriş için [**bu sayfayı okuyun**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Oku

Flipper Zero **NFC kartlarını okuyabilir**, ancak **ISO 14443'e dayanan tüm protokolleri anlamaz**. Ancak, **UID düşük seviyeli bir özellik olduğundan**, **UID zaten okunmuşken, yüksek seviyeli veri aktarım protokolü hala bilinmiyor** durumuyla karşılaşabilirsiniz. UID'yi okuma, taklit etme ve manuel olarak girme işlemini Flipper ile UID'yi yetkilendirme için kullanan ilkel okuyucular için gerçekleştirebilirsiniz.

#### UID Okuma VS İçerideki Veriyi Okuma <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

Flipper'da 13.56 MHz etiketlerini okuma iki parçaya ayrılabilir:

* **Düşük seviyeli okuma** — yalnızca UID, SAK ve ATQA'yı okur. Flipper, karttan okunan bu veriye dayanarak yüksek seviyeli protokolü tahmin etmeye çalışır. Bununla %100 emin olamazsınız, çünkü bu belirli faktörlere dayanan bir varsayımdır.
* **Yüksek seviyeli okuma** — belirli bir yüksek seviyeli protokol kullanarak kartın belleğinden verileri okur. Bu, bir Mifare Ultralight üzerindeki verileri okumak, bir Mifare Classic'ten sektörleri okumak veya PayPass/Apple Pay'den kartın özelliklerini okumak anlamına gelir.

### Belirli Okuma

Flipper Zero, düşük seviyeli verilerden kart türünü bulamıyorsa, `Ekstra Eylemler` bölümünde `Belirli Kart Türünü Oku` seçeneğini seçebilir ve **manuel olarak okumak istediğiniz kart türünü belirtebilirsiniz**.

#### EMV Banka Kartları (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Sadece UID'yi okumakla kalmayıp, bir banka kartından çok daha fazla veri çıkarabilirsiniz. **Tam kart numarasını** (kartın önündeki 16 haneli numara), **geçerlilik tarihini** ve bazı durumlarda **sahibinin adını** ve **en son işlemlerin** listesini almak mümkündür.\
Ancak, bu şekilde **CVV'yi okuyamazsınız** (kartın arkasındaki 3 haneli numara). Ayrıca **banka kartları yeniden oynatma saldırılarından korunmaktadır**, bu nedenle Flipper ile kopyalamak ve ardından bir şeyler ödemek için taklit etmeye çalışmak işe yaramayacaktır.

## Referanslar

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
