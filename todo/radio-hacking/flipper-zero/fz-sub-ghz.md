# FZ - Sub-GHz

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek.

</details>

## Giriş <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero, yerleşik modülü aracılığıyla **300-928 MHz aralığında radyo frekanslarını alıp ve iletebilir**. Bu modül uzaktan kumandaları okuyabilir, kaydedebilir ve taklit edebilir. Bu kumandalar, kapılar, bariyerler, radyo kilitleri, uzaktan kumandalı anahtarlar, kablosuz kapı zilleri, akıllı ışıklar ve daha fazlası ile etkileşim için kullanılır. Flipper Zero, güvenliğinizin tehlikeye atılıp atılmadığını öğrenmenize yardımcı olabilir.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz donanımı <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero, [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 çipi](https://www.ti.com/lit/ds/symlink/cc1101.pdf) ve bir radyo antenine dayalı yerleşik bir sub-1 GHz modüle sahiptir (maksimum menzil 50 metredir). Hem CC1101 çipi hem de anten, 300-348 MHz, 387-464 MHz ve 779-928 MHz bantlarında çalışacak şekilde tasarlanmıştır.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Eylemler

### Frekans Analizörü

{% hint style="info" %}
Uzaktan kumandanın hangi frekansı kullandığını bulma
{% endhint %}

Analiz yaparken, Flipper Zero frekans konfigürasyonunda mevcut olan tüm frekanslarda sinyal gücünü (RSSI) tarar. Flipper Zero, -90 [dBm](https://en.wikipedia.org/wiki/DBm)'den yüksek sinyal gücüne sahip olan en yüksek RSSI değerine sahip frekansı ekranda gösterir.

Uzaktan kumandanın frekansını belirlemek için şunları yapın:

1. Uzaktan kumandayı Flipper Zero'nun soluna çok yakın bir yere yerleştirin.
2. **Ana Menü**'ye gidin **→ Sub-GHz**.
3. **Frekans Analizörü'nü** seçin, ardından analiz etmek istediğiniz uzaktan kumandadaki düğmeye basılı tutun.
4. Ekranda frekans değerini inceleyin.

### Oku

{% hint style="info" %}
Kullanılan frekans hakkında bilgi bulma (ayrıca hangi frekansın kullanıldığını bulmanın başka bir yolu)
{% endhint %}

**Oku** seçeneği, varsayılan olarak 433.92 AM modülasyonunda yapılandırılmış frekansta dinleme yapar. **Okuma sırasında bir şey bulunursa**, ekran üzerinde **bilgi verilir**. Bu bilgi, gelecekte sinyali çoğaltmak için kullanılabilir.

Okuma sırasında, **sol düğmeye basarak** ve **yapılandırarak** kullanılabilir.\
Şu anda **4 modülasyon** (AM270, AM650, FM328 ve FM476) ve **çeşitli ilgili frekanslar** saklanmış durumda:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Sizi ilgilendiren **herhangi birini ayarlayabilirsiniz**, ancak eğer sahip olduğunuz uzaktan kumanda tarafından kullanılan frekansı **kesin olarak bilmiyorsanız Hopping'i ON** (varsayılan olarak Off) yapın ve Flipper'ın yakalayıp ihtiyacınız olan bilgiyi vermesi için düğmeye birkaç kez basın.

{% hint style="danger" %}
Frekanslar arasında geçiş biraz zaman alır, bu nedenle geçiş sırasında iletilen sinyaller kaçırılabilir. Daha iyi sinyal alımı için Frekans Analizörü tarafından belirlenen sabit bir frekans ayarlayın.
{% endhint %}

### **Ham Oku**

{% hint style="info" %}
Yapılandırılmış frekansta bir sinyali çalın (ve tekrarlayın)
{% endhint %}

**Ham Oku** seçeneği, dinleme frekansında gönderilen sinyalleri kaydeder. Bu, bir sinyali **çalmak** ve **tekrarlamak** için kullanılabilir.

Varsayılan olarak **Ham Oku da 433.92'de AM650'de** bulunur, ancak Oku seçeneği ile ilginizi çeken sinyalin farklı bir frekans/modülasyonda olduğunu bulursanız, bunu da değiştirebilirsiniz sol düğmeye basarak (Ham Oku seçeneği içindeyken).

### Kaba Kuvvet

Örneğin garaj kapısı tarafından kullanılan protokolü biliyorsanız, **tüm kodları oluşturabilir ve Flipper Zero ile gönderebilirsiniz**. Bu, genel olarak yaygın garaj tiplerini destekleyen bir örnektir: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Manuel Olarak Ekle

{% hint style="info" %}
Yapılandırılmış protokoller listesinden sinyal ekleyin
{% endhint %}

#### [Desteklenen protokollerin](https://docs.flipperzero.one/sub-ghz/add-new-remote) listesi <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (statik kod sistemlerinin çoğuyla çalışır) | 433.92 | Statik  |
| -------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                    | 433.92 | Statik  |
| Nice Flo 24bit\_433                                    | 433.92 | Statik  |
| CAME 12bit\_433                                        | 433.92 | Statik  |
| CAME 24bit\_433                                        | 433.92 | Statik  |
| Linear\_300                                            | 300.00 | Statik  |
| CAME TWEE                                              | 433.92 | Statik  |
| Gate TX\_433                                           | 433.92 | Statik  |
| DoorHan\_315                                           | 315.00 | Dinamik |
| DoorHan\_433                                           | 433.92 | Dinamik |
| LiftMaster\_315                                        | 315.00 | Dinamik |
| LiftMaster\_390                                        | 390.00 | Dinamik |
| Security+2.0\_310                                      | 310.00 | Dinamik |
| Security+2.0\_315                                      | 315.00 | Dinamik |
| Security+2.0\_390                                      | 390.00 | Dinamik |
### Desteklenen Sub-GHz Satıcıları

Listeye [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors) adresinden bakın.

### Bölgeye Göre Desteklenen Frekanslar

Listeye [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies) adresinden bakın.

### Test

{% hint style="info" %}
Kaydedilen frekansların dBm'lerini alın
{% endhint %}

## Referans

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)
