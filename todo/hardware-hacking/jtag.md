# JTAG

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR gönderin.

</details>

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum), bir Raspberry PI veya bir Arduino ile kullanılabilen bir araçtır ve bilinmeyen bir çipten JTAG pinlerini bulmaya çalışmak için kullanılabilir.\
**Arduino**'da, **2 ila 11 pinleri Arduino'ya bağlayın ve 10 pinleri potansiyel olarak bir JTAG'a ait olabilir.** Arduino'ya programı yükleyin ve tüm pinleri bruteforce ederek herhangi bir pinin JTAG'a ait olup olmadığını ve hangi pinin hangi olduğunu bulmaya çalışacaktır.\
**Raspberry PI**'da sadece **1 ila 6 pinleri** (6 pin, bu yüzden her potansiyel JTAG pini test etmek için daha yavaş ilerleyeceksiniz).

### Arduino

Arduino'da, kabloları bağladıktan sonra (pin 2 ila 11'i JTAG pinlerine ve Arduino GND'yi ana kart GND'ye bağlayın), **Arduino'ya JTAGenum programını yükleyin** ve Seri Monitörde bir **`h`** (yardım komutu) gönderin ve yardımı görmelisiniz:

![](<../../.gitbook/assets/image (939).png>)

![](<../../.gitbook/assets/image (578).png>)

**"Satır sonu yok" ve 115200baud**'u yapılandırın.\
Taramayı başlatmak için komut s'yi gönderin:

![](<../../.gitbook/assets/image (774).png>)

Bir JTAG ile iletişime geçiyorsanız, JTAG'ın pinlerini belirten bir veya birkaç **FOUND!** ile başlayan satır bulacaksınız.
