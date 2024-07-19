# FZ - Kızılötesi

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

## Giriş <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Kızılötesinin nasıl çalıştığı hakkında daha fazla bilgi için kontrol edin:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Flipper Zero'daki IR Sinyal Alıcısı <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper, IR uzaktan kumandalardan sinyalleri **yakalamayı** sağlayan dijital bir IR sinyal alıcısı TSOP kullanır. Xiaomi gibi bazı **akıllı telefonlar** da IR portuna sahiptir, ancak **çoğu yalnızca** sinyal **gönderebilir** ve **almaktan acizdir**.

Flipper'ın kızılötesi **alıcı oldukça hassastır**. Uzaktan kumanda ile TV arasında **bir yerde** kalırken bile **sinyali yakalayabilirsiniz**. Uzaktan kumandayı doğrudan Flipper'ın IR portuna doğrultmak gereksizdir. Bu, birinin TV'nin yanında dururken kanalları değiştirmesi durumunda işe yarar ve hem siz hem de Flipper bir mesafede olursunuz.

**Kızılötesi** sinyalin **çözülmesi** yazılım tarafında gerçekleştiğinden, Flipper Zero potansiyel olarak **herhangi bir IR uzaktan kumanda kodunun** alımını ve iletimini destekler. Tanınamayan **protokoller** durumunda - **ham sinyali** tam olarak alındığı gibi **kaydedip tekrar oynatır**.

## Eylemler

### Evrensel Uzaktan Kumandalar

Flipper Zero, herhangi bir TV, klima veya medya merkeziyi kontrol etmek için **evrensel bir uzaktan kumanda** olarak kullanılabilir. Bu modda, Flipper **SD karttan gelen sözlüğe** göre tüm desteklenen üreticilerin **bilinen kodlarını** **brute force** yapar. Bir restoran TV'sini kapatmak için belirli bir uzaktan kumanda seçmenize gerek yoktur.

Evrensel Uzaktan Kumanda modunda güç düğmesine basmak yeterlidir ve Flipper, bildiği tüm TV'lerin "Gücü Kapat" komutlarını **sırasıyla gönderecektir**: Sony, Samsung, Panasonic... ve devam eder. TV sinyalini aldığında, tepki verecek ve kapanacaktır.

Bu tür bir brute-force zaman alır. Sözlük ne kadar büyükse, tamamlanması o kadar uzun sürer. TV'nin tam olarak hangi sinyali tanıdığını öğrenmek imkansızdır çünkü TV'den geri bildirim yoktur.

### Yeni Uzaktan Kumanda Öğren

Flipper Zero ile **kızılötesi bir sinyali** **yakalamak** mümkündür. Eğer **veritabanında sinyali bulursa**, Flipper otomatik olarak **bu cihazın ne olduğunu bilecektir** ve sizin onunla etkileşimde bulunmanıza izin verecektir.\
Eğer bulamazsa, Flipper **sinyali saklayabilir** ve **tekrar oynatmanıza** izin verecektir.

## Referanslar

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

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
