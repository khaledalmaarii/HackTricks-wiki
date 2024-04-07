# JTAG

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum), bir Raspberry PI veya Arduino ile kullanılabilen bir araçtır ve bilinmeyen bir çipten JTAG pinlerini bulmaya çalışır.\
**Arduino**'da, **2 ila 11 pinleri Arduino'ya bağlayın ve 10 pinlik potansiyel bir JTAG'e ait olabilecek pinlere bağlayın**. Arduino'ya programı yükleyin ve tüm pinleri bruteforce ederek hangi pinlerin JTAG'e ait olduğunu ve her birinin hangisi olduğunu bulmaya çalışacaktır.\
**Raspberry PI**'da sadece **1 ila 6 pinleri** kullanabilirsiniz (6 pin, bu nedenle her potansiyel JTAG pini test etmek için daha yavaş ilerleyeceksiniz).

### Arduino

Arduino'da, kabloları bağladıktan sonra (pin 2 ila 11'i JTAG pinlerine ve Arduino GND'yi ana kart GND'ye bağlayın), **Arduino'ya JTAGenum programını yükleyin** ve Seri Monitörde bir **`h`** (yardım komutu) gönderin ve yardımı görmelisiniz:

![](<../../.gitbook/assets/image (936).png>)

![](<../../.gitbook/assets/image (575).png>)

**"Satır sonu yok" ve 115200baud**'u yapılandırın.\
Taramayı başlatmak için komut s'yi gönderin:

![](<../../.gitbook/assets/image (771).png>)

Bir JTAG ile iletişime geçiyorsanız, JTAG'in pinlerini belirten bir veya birkaç **FOUND!** ile başlayan satır bulacaksınız.
