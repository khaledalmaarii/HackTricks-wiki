# Android Forensiği

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>

## Kilitli Cihaz

Bir Android cihazdan veri çıkarmaya başlamak için kilidinin açık olması gerekir. Eğer kilitli ise şunları yapabilirsiniz:

* Cihazın USB üzerinden hata ayıklama özelliğinin etkin olup olmadığını kontrol edin.
* Muhtemel bir [iz bırakma saldırısını](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf) kontrol edin.
* [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/) ile deneyin.

## Veri Edinme

Bir [adb kullanarak android yedekleme oluşturun](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) ve [Android Yedek Çıkartıcı](https://sourceforge.net/projects/adbextractor/) kullanarak çıkartın: `java -jar abe.jar unpack file.backup file.tar`

### Root erişimi veya JTAG arabirimine fiziksel bağlantı varsa

* `cat /proc/partitions` (flash belleğin yolunu arayın, genellikle ilk giriş _mmcblk0_ ve tüm flash belleğe karşılık gelir).
* `df /data` (Sistemin blok boyutunu keşfedin).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (blok boyutundan elde edilen bilgilerle çalıştırın).

### Bellek

RAM bilgilerini çıkarmak için Linux Memory Extractor (LiME) kullanın. Bu, adb aracılığıyla yüklenmesi gereken bir çekirdek uzantısıdır.

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>
