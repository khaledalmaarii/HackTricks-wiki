# Android Forensik

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

## Gesperrtes Gerät

Um Daten von einem Android-Gerät zu extrahieren, muss es entsperrt sein. Wenn es gesperrt ist, kannst du:

* Überprüfen, ob das Gerät das Debugging über USB aktiviert hat.
* Nach einem möglichen [Smudge-Angriff](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf) suchen.
* Es mit [Brute-Force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/) versuchen.

## Datenerfassung

Erstelle ein [Android-Backup mit adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) und extrahiere es mit dem [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Wenn Root-Zugriff oder physische Verbindung zur JTAG-Schnittstelle

* `cat /proc/partitions` (suche den Pfad zum Flash-Speicher, in der Regel ist der erste Eintrag _mmcblk0_ und entspricht dem gesamten Flash-Speicher).
* `df /data` (Entdecke die Blockgröße des Systems).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (führe es mit den Informationen aus der Blockgröße aus).

### Speicher

Verwende den Linux Memory Extractor (LiME), um die RAM-Informationen zu extrahieren. Es ist eine Kernel-Erweiterung, die über adb geladen werden sollte.

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
