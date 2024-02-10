<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


# JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum), bilinmeyen bir yongadaki JTAG pinlerini bulmak için bir Raspberry PI veya Arduino ile kullanılabilen bir araçtır.\
**Arduino**'da, **2 ila 11 pinlerini potansiyel olarak bir JTAG'ye ait olabilecek 10 pine** bağlayın. Arduino'ya programı yükleyin ve tüm pinleri bruteforce yaparak JTAG'ye ait olanları ve her birinin hangisi olduğunu bulmaya çalışacaktır.\
**Raspberry PI**'da sadece **1 ila 6 pinleri** (6 pin, bu nedenle her bir potansiyel JTAG pini için yavaşça test yapacaksınız) kullanabilirsiniz.

## Arduino

Arduino'da, kabloları bağladıktan sonra (pin 2 ila 11'i JTAG pinlerine ve Arduino GND'sini ana kart GND'sine bağlayın), Arduino'ya **JTAGenum programını yükleyin** ve Seri Monitörde bir **`h`** (yardım komutu) gönderin ve yardımı görmelisiniz:

![](<../../.gitbook/assets/image (643).png>)

![](<../../.gitbook/assets/image (650).png>)

**"No line ending" ve 115200baud** ayarlayın.\
Taramayı başlatmak için komutu s gönderin:

![](<../../.gitbook/assets/image (651) (1) (1) (1).png>)

Bir JTAG ile iletişim kuruyorsanız, JTAG pinlerini gösteren bir veya birkaç **FOUND! ile başlayan satır** bulacaksınız.


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
