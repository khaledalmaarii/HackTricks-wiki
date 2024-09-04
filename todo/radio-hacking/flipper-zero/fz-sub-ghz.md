# FZ - Sub-GHz

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}


## Giriş <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero, **uzaktan kumandaları okuyabilen, kaydedebilen ve taklit edebilen yerleşik modülü ile 300-928 MHz aralığında radyo frekanslarını **alabilir ve iletebilir. Bu kontroller, kapılar, engeller, radyo kilitleri, uzaktan kumanda anahtarları, kablosuz kapı zilleri, akıllı ışıklar ve daha fazlası ile etkileşim için kullanılır. Flipper Zero, güvenliğinizin tehlikeye girip girmediğini öğrenmenize yardımcı olabilir.

<figure><img src="../../../.gitbook/assets/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz donanımı <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero, [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 çipi](https://www.ti.com/lit/ds/symlink/cc1101.pdf) ve bir radyo anteni (maksimum menzil 50 metredir) ile donatılmış yerleşik bir sub-1 GHz modülüne sahiptir. Hem CC1101 çipi hem de antena, 300-348 MHz, 387-464 MHz ve 779-928 MHz bantlarında çalışacak şekilde tasarlanmıştır.

<figure><img src="../../../.gitbook/assets/image (923).png" alt=""><figcaption></figcaption></figure>

## Eylemler

### Frekans Analizörü

{% hint style="info" %}
Uzaktan kumandanın hangi frekansı kullandığını nasıl bulabilirsiniz
{% endhint %}

Analiz sırasında, Flipper Zero, frekans yapılandırmasında mevcut olan tüm frekanslarda sinyal gücünü (RSSI) tarar. Flipper Zero, -90 [dBm](https://en.wikipedia.org/wiki/DBm) değerinden daha yüksek sinyal gücüne sahip en yüksek RSSI değerine sahip frekansı görüntüler.

Uzaktan kumandanın frekansını belirlemek için aşağıdakileri yapın:

1. Uzaktan kumandayı Flipper Zero'nun soluna çok yakın bir yere yerleştirin.
2. **Ana Menü** **→ Sub-GHz**'ye gidin.
3. **Frekans Analizörü**'nü seçin, ardından analiz etmek istediğiniz uzaktan kumanda üzerindeki düğmeye basılı tutun.
4. Ekrandaki frekans değerini gözden geçirin.

### Oku

{% hint style="info" %}
Kullanılan frekans hakkında bilgi bulun (aynı zamanda hangi frekansın kullanıldığını bulmanın başka bir yolu)
{% endhint %}

**Oku** seçeneği, belirtilen modülasyonda **yapılandırılmış frekansta dinler**: varsayılan olarak 433.92 AM. Eğer **okuma sırasında bir şey bulunursa**, ekranda **bilgi verilir**. Bu bilgi, gelecekte sinyali çoğaltmak için kullanılabilir.

Okuma kullanılırken, **sol düğmeye** basıp **yapılandırmak** mümkündür.\
Bu anda **4 modülasyon** (AM270, AM650, FM328 ve FM476) ve **birçok ilgili frekans** saklanmıştır:

<figure><img src="../../../.gitbook/assets/image (947).png" alt=""><figcaption></figcaption></figure>

**İlginizi çeken herhangi birini** ayarlayabilirsiniz, ancak eğer **uzaktan kumandanızın hangi frekansı kullanabileceğinden emin değilseniz**, **Hopping'i AÇIK** (varsayılan olarak Kapalı) ayarlayın ve Flipper bunu yakalayana kadar düğmeye birkaç kez basın, ardından frekansı ayarlamak için ihtiyacınız olan bilgiyi alırsınız.

{% hint style="danger" %}
Frekanslar arasında geçiş yapmak biraz zaman alır, bu nedenle geçiş sırasında iletilen sinyaller kaçırılabilir. Daha iyi sinyal alımı için, Frekans Analizörü tarafından belirlenen sabit bir frekans ayarlayın.
{% endhint %}

### **Ham Oku**

{% hint style="info" %}
Yapılandırılmış frekansta bir sinyali çalın (ve tekrar edin)
{% endhint %}

**Ham Oku** seçeneği, dinleme frekansında gönderilen sinyalleri **kaydeder**. Bu, bir sinyali **çalmak** ve **tekrar etmek** için kullanılabilir.

Varsayılan olarak **Ham Oku da 433.92 AM650**'de bulunmaktadır, ancak Okuma seçeneği ile ilginizi çeken sinyalin **farklı bir frekans/modülasyonda olduğunu bulursanız, bunu da değiştirebilirsiniz** (Ham Oku seçeneği içindeyken sola basarak).

### Kaba Kuvvet

Eğer garaj kapısı tarafından kullanılan protokolü biliyorsanız, **tüm kodları üretebilir ve bunları Flipper Zero ile gönderebilirsiniz.** Bu, genel yaygın garaj türlerini destekleyen bir örnektir: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Manuel Ekle

{% hint style="info" %}
Yapılandırılmış bir protokol listesinde sinyalleri ekleyin
{% endhint %}

#### [desteklenen protokoller](https://docs.flipperzero.one/sub-ghz/add-new-remote) listesi <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (statik kod sistemlerinin çoğuyla çalışır) | 433.92 | Statik  |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433.92 | Statik  |
| Nice Flo 24bit\_433                                             | 433.92 | Statik  |
| CAME 12bit\_433                                                 | 433.92 | Statik  |
| CAME 24bit\_433                                                 | 433.92 | Statik  |
| Linear\_300                                                     | 300.00 | Statik  |
| CAME TWEE                                                       | 433.92 | Statik  |
| Gate TX\_433                                                    | 433.92 | Statik  |
| DoorHan\_315                                                    | 315.00 | Dinamik |
| DoorHan\_433                                                    | 433.92 | Dinamik |
| LiftMaster\_315                                                 | 315.00 | Dinamik |
| LiftMaster\_390                                                 | 390.00 | Dinamik |
| Security+2.0\_310                                               | 310.00 | Dinamik |
| Security+2.0\_315                                               | 315.00 | Dinamik |
| Security+2.0\_390                                               | 390.00 | Dinamik |

### Desteklenen Sub-GHz satıcıları

[https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors) adresindeki listeyi kontrol edin.

### Bölgeye göre desteklenen frekanslar

[https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies) adresindeki listeyi kontrol edin.

### Test

{% hint style="info" %}
Kaydedilen frekansların dBms'ini alın
{% endhint %}

## Referans

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
