# FZ - NFC

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz? Şirketinizin HackTricks'te reklamını görmek ister misiniz? Ya da PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz.
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* **💬** [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya beni **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin**.
* **Hacking püf noktalarınızı göndererek HackTricks deposuna** [**PR göndererek**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud deposuna**](https://github.com/carlospolop/hacktricks-cloud) **katkıda bulunun**.

</details>

## Giriş <a href="#id-9wrzi" id="id-9wrzi"></a>

RFID ve NFC hakkında bilgi için aşağıdaki sayfaya bakın:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Desteklenen NFC kartları <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
NFC kartları dışında Flipper Zero, birkaç **Mifare** Classic ve Ultralight ve **NTAG** gibi **yüksek frekanslı kart türlerini** destekler.
{% endhint %}

Yeni türdeki NFC kartlar desteklenen kartlar listesine eklenecektir. Flipper Zero, aşağıdaki **NFC kart türlerini A** (ISO 14443A) destekler:

* **Banka kartları (EMV)** — yalnızca UID, SAK ve ATQA'yı okurken kaydetmez.
* **Bilinmeyen kartlar** — (UID, SAK, ATQA) okur ve bir UID taklit eder.

**NFC kartları türü B, türü F ve türü V** için, Flipper Zero bir UID okuyabilir ancak kaydetmez.

### NFC kartları türü A <a href="#uvusf" id="uvusf"></a>

#### Banka kartı (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero, yalnızca bir UID, SAK, ATQA ve banka kartlarındaki depolanan verileri **kaydetmeden** okuyabilir.

Banka kartı okuma ekranı Banka kartları için, Flipper Zero verileri yalnızca okuyabilir **kaydetmeden ve taklit etmeden**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Bilinmeyen kartlar <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zero, **NFC kartının türünü belirleyemediğinde**, yalnızca bir **UID, SAK ve ATQA** okunabilir ve **kaydedilebilir**.

Bilinmeyen kart okuma ekranı Bilinmeyen NFC kartları için, Flipper Zero yalnızca bir UID taklit edebilir.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC kartları türleri B, F ve V <a href="#wyg51" id="wyg51"></a>

**NFC kartları türleri B, F ve V** için, Flipper Zero yalnızca bir UID **okuyabilir ve görüntüleyebilir** ancak kaydetmez.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## İşlemler

NFC hakkında bir giriş için [**bu sayfayı okuyun**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Oku

Flipper Zero, **NFC kartlarını okuyabilir**, ancak **ISO 14443'e dayanan tüm protokolleri anlamaz**. Ancak, çünkü **UID düşük seviye bir özelliktir**, **UID'nin zaten okunduğu ancak yüksek seviye veri transfer protokolünün hala bilinmediği bir durumda bulunabilirsiniz**. Flipper'ı kullanarak UID'yi okuyabilir, taklit edebilir ve manuel olarak UID'yi giriş yapabilirsiniz, UID'yi yetkilendirme için UID kullanan ilkel okuyucular için.

#### UID'yi Okuma VS İçindeki Veriyi Okuma <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

Flipper'da, 13.56 MHz etiketlerini okuma iki bölüme ayrılabilir:

* **Düşük seviye okuma** — Yalnızca UID, SAK ve ATQA'yı okur. Flipper, karttan okunan bu verilere dayanarak yüksek seviye protokolü tahmin etmeye çalışır. Bu, belirli faktörlere dayalı bir varsayımdan ibaret olduğundan %100 emin olamazsınız.
* **Yüksek seviye okuma** — Belirli bir yüksek seviye protokol kullanarak kartın belleğinden veri okur. Bu, Mifare Ultralight'tan veri okumak, Mifare Classic'ten sektörleri okumak veya PayPass/Apple Pay'den kartın özelliklerini okumak olabilir.

### Belirli Oku

Flipper Zero, düşük seviye verilerden kartın türünü bulamıyorsa, `Ekstra İşlemler`de `Belirli Kart Türünü Oku` seçeneğini seçebilir ve **okumak istediğiniz kart türünü manuel olarak belirtebilirsiniz**.

#### EMV Banka Kartları (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

UID'yi yalnızca okumanın ötesinde, bir banka kartından çok daha fazla veri çıkarabilirsiniz. **Tam kart numarasını** (kartın önündeki 16 haneli sayı), **geçerlilik tarihini** ve bazı durumlarda hatta **sahibin adını** ve **en son işlemler listesini** alabilirsiniz.\
Ancak, bu şekilde **CVV'yi** (kartın arkasındaki 3 haneli sayı) **okuyamazsınız**. Ayrıca **banka kartları replay saldırılarına karşı korunmuştur**, bu nedenle Flipper ile kopyalayıp ardından bir şey satın almak için taklit etmeye çalışmak çalışmaz.
## Referanslar

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Sıfırdan kahraman olacak şekilde AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz? Şirketinizin HackTricks'te reklamını görmek ister misiniz? Ya da en son PEASS sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) **kontrol edin!**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz**
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) **Discord grubuna**](https://discord.gg/hRep4RUj7f) **veya** [**telegram grubuna**](https://t.me/peass) **katılın veya beni Twitter'da takip edin** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Hacking püf noktalarınızı göndererek HackTricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo'ya**](https://github.com/carlospolop/hacktricks-cloud) **PR göndererek paylaşın.**

</details>
