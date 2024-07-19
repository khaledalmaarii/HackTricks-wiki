# JTAG

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum), bilinmeyen bir çipten JTAG pinlerini bulmak için bir Raspberry PI veya Arduino ile kullanılabilecek bir araçtır.\
**Arduino'da**, **2'den 11'e kadar olan pinleri JTAG'a ait olabilecek 10 pinle bağlayın**. Programı Arduino'ya yükleyin ve tüm pinleri brute force ile denemeye çalışacaktır. JTAG'a ait olan pinleri ve her birinin hangisi olduğunu bulacaktır.\
**Raspberry PI'da** yalnızca **1'den 6'ya kadar olan pinleri** kullanabilirsiniz (6 pin, bu nedenle her potansiyel JTAG pinini test ederken daha yavaş gideceksiniz).

### Arduino

Arduino'da, kabloları bağladıktan sonra (pin 2'den 11'e kadar JTAG pinlerine ve Arduino GND'yi ana kart GND'ye bağlayarak), **JTAGenum programını Arduino'ya yükleyin** ve Seri Monitörde **`h`** (yardım komutu) gönderin ve yardım mesajını görmelisiniz:

![](<../../.gitbook/assets/image (939).png>)

![](<../../.gitbook/assets/image (578).png>)

**"No line ending" ve 115200baud** ayarlarını yapın.\
Tarama başlatmak için s komutunu gönderin:

![](<../../.gitbook/assets/image (774).png>)

Eğer bir JTAG ile iletişim kuruyorsanız, JTAG pinlerini belirten **FOUND!** ile başlayan bir veya daha fazla **satır bulacaksınız**.

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
