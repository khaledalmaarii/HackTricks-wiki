# Android Forenzika

{% hint style="success" %}
Naučite i vežbajte AWS Hakovanje:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte GCP Hakovanje: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## Zaključan uređaj

Da biste počeli sa izvlačenjem podataka sa Android uređaja, mora biti otključan. Ako je zaključan, možete:

* Proverite da li je na uređaju aktivirano debagovanje putem USB-a.
* Proverite mogući [napad na otiske prstiju](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf)
* Pokušajte sa [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Akvizicija podataka

Napravite [android rezervnu kopiju korišćenjem adb](mobile-pentesting/android-app-pentesting/adb-commands.md#backup) i izvucite je koristeći [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Ako imate root pristup ili fizičku vezu sa JTAG interfejsom

* `cat /proc/partitions` (potražite putanju do fleš memorije, obično je prva stavka _mmcblk0_ i odgovara celoj fleš memoriji).
* `df /data` (Otkrijte veličinu bloka sistema).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (izvršite sa informacijama prikupljenim o veličini bloka).

### Memorija

Koristite Linux Memory Extractor (LiME) da izvučete informacije o RAM-u. To je kernel ekstenzija koja bi trebalo da se učita putem adb.

{% hint style="success" %}
Naučite i vežbajte AWS Hakovanje:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte GCP Hakovanje: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
