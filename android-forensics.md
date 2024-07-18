# Analiza danych na urządzeniach z systemem Android

{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
{% endhint %}

## Zablokowane urządzenie

Aby rozpocząć ekstrakcję danych z urządzenia z systemem Android, musi być ono odblokowane. Jeśli jest zablokowane, możesz:

* Sprawdź, czy na urządzeniu jest aktywowane debugowanie przez USB.
* Sprawdź możliwość [ataku smugowego](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf)
* Spróbuj z [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Pozyskiwanie danych

Utwórz [kopię zapasową Androida za pomocą adb](mobile-pentesting/android-app-pentesting/adb-commands.md#backup) i wyodrębnij ją za pomocą [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Jeśli masz dostęp do roota lub fizyczne połączenie z interfejsem JTAG

* `cat /proc/partitions` (znajdź ścieżkę do pamięci flash, zazwyczaj pierwszy wpis to _mmcblk0_ i odpowiada całej pamięci flash).
* `df /data` (Odkryj rozmiar bloku systemu).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (wykonaj to z informacjami zebranymi z rozmiaru bloku).

### Pamięć

Użyj Linux Memory Extractor (LiME), aby wyodrębnić informacje o pamięci RAM. Jest to rozszerzenie jądra, które powinno być załadowane za pomocą adb.

{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
{% endhint %}
