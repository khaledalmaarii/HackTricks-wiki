# FZ - Sub-GHz

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam vermek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud github depolarına PR göndererek paylaşın** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun ve daha hızlı düzeltin. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Giriş <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero, yerleşik modülüyle **300-928 MHz aralığındaki radyo frekanslarını alıp iletebilir**. Bu modül, uzaktan kumandaları okuyabilir, kaydedebilir ve taklit edebilir. Bu kumandalar, kapılar, bariyerler, radyo kilitleri, uzaktan kumanda anahtarları, kablosuz kapı zilleri, akıllı ışıklar ve daha fazlasıyla etkileşim için kullanılır. Flipper Zero, güvenliğinizin tehlikeye atılıp atılmadığını öğrenmenize yardımcı olabilir.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz donanımı <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero, [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 çipi](https://www.ti.com/lit/ds/symlink/cc1101.pdf) ve bir radyo anteni (maksimum menzil 50 metre) üzerinde çalışan yerleşik bir sub-1 GHz modülüne sahiptir. Hem CC1101 çipi hem de anten, 300-348 MHz, 387-464 MHz ve 779-928 MHz bantlarında çalışacak şekilde tasarlanmıştır.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## İşlemler

### Frekans Analizörü

{% hint style="info" %}
Uzaktan kumandanın hangi frekansı kullandığını bulma
{% endhint %}

Analiz yaparken, Flipper Zero frekans yapılandırmasında mevcut olan tüm frekanslarda sinyal gücünü (RSSI) tarar. Flipper Zero, -90 [dBm](https://en.wikipedia.org/wiki/DBm)'den daha yüksek sinyal gücüne sahip olan en yüksek RSSI değerine sahip frekansı ekranda gösterir.

Uzaktan kumandanın frekansını belirlemek için aşağıdaki adımları izleyin:

1. Uzaktan kumandayı Flipper Zero'nun soluna çok yakın bir yere yerleştirin.
2. **Ana Menü**'ye gidin **→ Sub-GHz**.
3. **Frekans Analizörü'nü** seçin, ardından analiz yapmak istediğiniz uzaktan kumandanın düğmesini basılı tutun.
4. Ekran üzerindeki frekans değerini inceleyin.

### Oku

{% hint style="info" %}
Kullanılan frekans hakkında bilgi bulma (aynı zamanda hangi frekansın kullanıldığını bulmanın başka bir yolu)
{% endhint %}

**Oku** seçeneği, belirtilen modülasyonda (varsayılan olarak 433.92 AM) yapılandırılmış frekansta **dinleme yapar**. Okuma sırasında **bir şey bulunursa**, bilgi ekranında verilir. Bu bilgi, sinyali gelecekte tekrarlamak için kullanılabilir.

Okuma kullanılırken, **sol düğmeye basarak** ve **onu yapılandırarak** ayarlanabilir.\
Şu anda **4 modülasyon** (AM270, AM650, FM328 ve FM476) ve **birkaç önemli frekans** bulunmaktadır:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

**İlgilendiğiniz herhangi birini** ayarlayabilirsiniz, ancak eğer sahip olduğunuz uzaktan kumandanın hangi frekansı kullandığından **emin değilseniz, Hopping'i ON** (varsayılan olarak Off) olarak ayarlayın ve Flipper yakalayana kadar düğmeye birkaç kez basın ve ihtiyacınız olan bilgiyi size vermesini bekleyin.

{% hint style="danger" %}
Frekanslar arasında geçiş yapmak biraz zaman alır, bu nedenle geçiş sırasında iletilen sinyaller kaçırılabilir. Daha iyi bir sinyal alımı için, Frekans Analizörü tarafından belirlenen sabit bir frekans ayarlayın.
{% endhint %}

### **Ham Oku**

{% hint style="info" %}
Yapılandırılmış frekansta bir sinyali çalın (ve tekrarlayın)
{% endhint %}

**Ham Oku** seçeneği, dinleme frekansında gönderilen sinyalleri kaydeder. Bu, bir sinyali **çalmak** ve **tekrarlamak** için kullanılabilir.

Varsayılan olarak, **Ham Oku** da 433.92 AM650'de bulunur, ancak Oku seçeneğiyle ilgilendiğiniz sinyalin farklı bir frekansta/modülasyonda olduğunu bulduysanız, sol düğmeye basarak bunu da değiştirebilirsiniz (Ham Oku seçeneği içindeyken).

### Kaba Kuvvet

Örneğin garaj kapısının kullandığı protokolü biliyorsanız, **Flipper Zero ile tüm kodları oluşturabilir ve gönderebilirsiniz**. Bu, genel olarak yaygın garaj tiplerini destekleyen bir örnektir: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)\*\*\*\*

### Elle Ekle

{% hint style="info" %}
Yapılandırılmış protokol listesinden sinyaller ekleyin
{% endhint %}

#### [Desteklenen protokollerin](https://docs.flipperzero.one/sub-ghz/add-new-remote) listesi <a href="#3iglu" id="3iglu"></a>

| Princeton\_433 (çoğu statik kod sistemleriyle çalışır) | 433.92 | Statik  |
| ---------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                  | 433.92 | Statik  |
| Nice Flo 24bit\_433                                  | 433.92 | Statik  |
| CAME 12
### Desteklenen Sub-GHz Satıcıları

[https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors) adresindeki listede kontrol edin.

### Bölgeye Göre Desteklenen Frekanslar

[https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies) adresindeki listede kontrol edin.

### Test

{% hint style="info" %}
Kaydedilen frekansların dBm değerlerini alın.
{% endhint %}

## Referans

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

En önemli güvenlik açıklarını bulun, böylece daha hızlı düzeltebilirsiniz. Intruder saldırı yüzeyinizi takip eder, proaktif tehdit taramaları yapar, API'lerden web uygulamalarına ve bulut sistemlerine kadar tüm teknoloji yığınınızda sorunları bulur. [**Ücretsiz deneyin**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) bugün.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olacak şekilde öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklam vermek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'ler**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>
