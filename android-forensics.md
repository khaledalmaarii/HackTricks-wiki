# Android Forensik

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı takip edin**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

## Kilitli Cihaz

Bir Android cihazdan veri çıkarmaya başlamak için cihazın kilidinin açık olması gerekmektedir. Eğer kilitli ise şunları yapabilirsiniz:

* Cihazın USB üzerinden hata ayıklamaya sahip olup olmadığını kontrol edin.
* Olası bir [parmak izi saldırısını](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf) kontrol edin.
* [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/) ile deneyin.

## Veri Edinimi

[adb kullanarak bir Android yedekleme](mobile-pentesting/android-app-pentesting/adb-commands.md#backup) oluşturun ve [Android Yedekleme Çıkarıcısı](https://sourceforge.net/projects/adbextractor/) kullanarak çıkarın: `java -jar abe.jar unpack file.backup file.tar`

### Root erişimi veya fiziksel bağlantı varsa JTAG arabirimine

* `cat /proc/partitions` (flash belleğin yolunu arayın, genellikle ilk giriş _mmcblk0_ ve tüm flash belleğe karşılık gelir).
* `df /data` (Sistemin blok boyutunu keşfedin).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (blok boyutundan elde edilen bilgilerle çalıştırın).

### Bellek

RAM bilgilerini çıkarmak için Linux Memory Extractor (LiME) kullanın. Bu, adb aracılığıyla yüklenmesi gereken bir çekirdek uzantısıdır.

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı takip edin**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>
