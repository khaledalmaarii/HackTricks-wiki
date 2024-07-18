# Android Adli Tıp

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** bizi takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Kilitli Cihaz

Bir Android cihazdan veri çıkarmaya başlamak için cihazın kilidinin açılması gerekir. Kilitli ise:

* Cihazın USB üzerinden hata ayıklamanın etkin olup olmadığını kontrol edin.
* Olası bir [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf) kontrol edin.
* [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/) ile deneyin.

## Veri Edinimi

Bir [android yedeği oluşturun](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) ve [Android Yedekleme Çıkarıcı](https://sourceforge.net/projects/adbextractor/) kullanarak çıkarın: `java -jar abe.jar unpack file.backup file.tar`

### Eğer root erişimi veya JTAG arayüzüne fiziksel bağlantı varsa

* `cat /proc/partitions` (flash belleğin yolunu arayın, genellikle ilk giriş _mmcblk0_ olup tüm flash belleği temsil eder).
* `df /data` (sistemin blok boyutunu keşfedin).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (blok boyutundan elde edilen bilgilerle çalıştırın).

### Bellek

RAM bilgilerini çıkarmak için Linux Bellek Çıkarıcı (LiME) kullanın. Bu, adb üzerinden yüklenmesi gereken bir çekirdek uzantısıdır. 

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** bizi takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
