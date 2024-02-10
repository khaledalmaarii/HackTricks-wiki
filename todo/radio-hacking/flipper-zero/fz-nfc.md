# FZ - NFC

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile göndererek paylaşın**.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Giriş <a href="#9wrzi" id="9wrzi"></a>

RFID ve NFC hakkında bilgi için aşağıdaki sayfayı kontrol edin:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Desteklenen NFC kartları <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
Flipper Zero, **Mifare** Classic ve Ultralight ve **NTAG** gibi birkaç **yüksek frekanslı kartın** yanı sıra **diğer tür NFC kartlarını** da destekler.
{% endhint %}

Desteklenen kartların listesine yeni NFC kart türleri eklenecektir. Flipper Zero, aşağıdaki **NFC kart türü A**'yı (ISO 14443A) destekler:

* ﻿**Banka kartları (EMV)** - Sadece UID, SAK ve ATQA okur ve kaydetmez.
* ﻿**Bilinmeyen kartlar** - UID, SAK, ATQA okur ve bir UID taklit eder.

**NFC kart türü B, tür F ve tür V** için, Flipper Zero bir UID okuyabilir ancak kaydetmez.

### NFC kartları türü A <a href="#uvusf" id="uvusf"></a>

#### Banka kartı (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero, banka kartlarının verilerini **kaydetmeden** sadece UID, SAK, ATQA ve depolanan verileri okuyabilir.

Banka kartı okuma ekranıFlipper Zero, banka kartları için verileri sadece **kaydetmeden ve taklit etmeden** okuyabilir.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Bilinmeyen kartlar <a href="#37eo8" id="37eo8"></a>

Flipper Zero, **NFC kartının türünü belirleyemezse**, yalnızca bir **UID, SAK ve ATQA** okunabilir ve kaydedilebilir.

Bilinmeyen kart okuma ekranıBilinmeyen NFC kartları için, Flipper Zero yalnızca bir UID taklit edebilir.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC kartları türleri B, F ve V <a href="#wyg51" id="wyg51"></a>

**NFC kartları türleri B, F ve V** için, Flipper Zero yalnızca bir UID okuyabilir ve görüntüleyebilir ancak kaydetmez.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## İşlemler

NFC hakkında bir giriş için [**bu sayfayı okuyun**](../../../radio-hacking/pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Oku

Flipper Zero, NFC kartlarını **okuyabilir**, ancak ISO 14443'e dayanan **tüm protokolleri anlamaz**. Ancak, **UID düşük seviye bir özellik** olduğu için, UID'nin zaten okunduğu ancak yüksek seviye veri transfer protokolünün hala bilinmediği bir durumda bulunabilirsiniz. Flipper, UID'yi yetkilendirme için UID kullanan ilkel okuyucular için UID'yi okuyabilir, taklit edebilir ve manuel olarak girebilirsiniz.

#### UID'yi Okuma VS İçindeki Veriyi Okuma <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Flipper'da, 13.56 MHz etiketlerini okuma iki bölüme ayrılabilir:

* **Düşük seviye okuma** - Yalnızca UID, SAK ve ATQA'yı okur. Flipper, karttan okunan bu verilere dayanarak yüksek seviye protokolü tahmin etmeye çalışır. Bu, belirli faktörlere dayanan bir varsayımdan ibaret olduğu için %100 emin olamazsınız.
* **Yüksek seviye okuma** - Belirli bir yüksek seviye protokol kullanarak kartın belleğinden veriyi okur. Bu, Mifare Ultralight'tan veri okuma, Mifare Classic'ten sektörleri okuma veya PayPass/Apple Pay'den kartın özelliklerini okuma olabilir.

### Belirli Bir Kartı Oku

Flipper Zero, düşük seviye verilerden kartın türünü bulamazsa, `Ekstra İşlemler` bölümünde `Belirli Kart Türünü Oku` seçeneğini seçebilir ve **okumak istediğiniz kart türünü manuel olarak belirtebilirsiniz**.
#### EMV Banka Kartları (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Sadece UID'yi okumaktan daha fazla veri çıkarabilirsiniz bir banka kartından. **Tam kart numarasını** (kartın ön yüzündeki 16 haneli sayı), **geçerlilik tarihini** ve bazı durumlarda hatta **sahibinin adını** bile alabilirsiniz, en **son işlemlerin bir listesiyle birlikte**.\
Ancak, bu şekilde CVV'yi okuyamazsınız (kartın arka yüzündeki 3 haneli sayı). Ayrıca, **banka kartları replay saldırılarına karşı korunur**, bu yüzden Flipper ile kopyalayıp sonra bir şey için taklit etmeye çalışarak ödeme yapamazsınız.

## Referanslar

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi hacktricks repo**'ya (https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **göndererek paylaşın**.

</details>
