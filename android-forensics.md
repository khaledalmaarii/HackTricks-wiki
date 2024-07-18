# Android Dijital Delil İnceleme

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

## Kilitli Cihaz

Bir Android cihazdan veri çıkarmaya başlamak için cihazın kilidinin açık olması gerekir. Eğer kilitli ise şunları yapabilirsiniz:

* Cihazın USB üzerinden hata ayıklama özelliğinin etkin olup olmadığını kontrol edin.
* Muhtemel bir [parmak izi saldırısını](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf) kontrol edin.
* [Kaba kuvvet](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/) ile deneyin.

## Veri Edinme

[adb kullanarak android yedekleme oluşturun](mobile-pentesting/android-app-pentesting/adb-commands.md#backup) ve [Android Yedek Çıkartıcı](https://sourceforge.net/projects/adbextractor/) kullanarak çıkartın: `java -jar abe.jar unpack file.backup file.tar`

### Root erişimi veya JTAG arabirimine fiziksel bağlantı varsa

* `cat /proc/partitions` (flash belleğin yolunu arayın, genellikle ilk giriş _mmcblk0_ ve tüm flash belleğe karşılık gelir).
* `df /data` (Sistemin blok boyutunu keşfedin).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (blok boyutundan elde edilen bilgilerle çalıştırın).

### Bellek

RAM bilgilerini çıkarmak için Linux Bellek Çıkartıcı (LiME) kullanın. Bu, adb aracılığıyla yüklenmesi gereken bir çekirdek uzantısıdır.

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}
