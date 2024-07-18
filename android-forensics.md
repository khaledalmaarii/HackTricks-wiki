# Android Forensik

{% hint style="success" %}
Lernen Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
{% endhint %}

## Gesperrtes Gerät

Um mit der Extraktion von Daten von einem Android-Gerät zu beginnen, muss es entsperrt sein. Wenn es gesperrt ist, können Sie:

* Überprüfen, ob das Gerät die USB-Debugging aktiviert hat.
* Überprüfen Sie auf einen möglichen [Fingerabdruckangriff](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf)
* Versuchen Sie es mit [Brute-Force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Datenbeschaffung

Erstellen Sie ein [Android-Backup mit adb](mobile-pentesting/android-app-pentesting/adb-commands.md#backup) und extrahieren Sie es mit [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Bei Root-Zugriff oder physischer Verbindung zum JTAG-Interface

* `cat /proc/partitions` (Suchen Sie den Pfad zum Flash-Speicher, normalerweise ist der erste Eintrag _mmcblk0_ und entspricht dem gesamten Flash-Speicher).
* `df /data` (Ermitteln Sie die Blockgröße des Systems).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (Führen Sie es mit den Informationen aus der Blockgröße aus).

### Speicher

Verwenden Sie den Linux Memory Extractor (LiME), um die RAM-Informationen zu extrahieren. Es handelt sich um eine Kernelerweiterung, die über adb geladen werden sollte.

{% hint style="success" %}
Lernen Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
{% endhint %}
