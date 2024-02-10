# Android Forensik

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Gesperrtes Gerät

Um Daten von einem Android-Gerät extrahieren zu können, muss es entsperrt sein. Wenn es gesperrt ist, können Sie Folgendes tun:

* Überprüfen Sie, ob das Gerät die USB-Debugging-Funktion aktiviert hat.
* Überprüfen Sie auf einen möglichen [Smudge-Angriff](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf)
* Versuchen Sie es mit [Brute-Force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Datenbeschaffung

Erstellen Sie ein [Android-Backup mit adb](mobile-pentesting/android-app-pentesting/adb-commands.md#backup) und extrahieren Sie es mit dem [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Bei Root-Zugriff oder physischer Verbindung zur JTAG-Schnittstelle

* `cat /proc/partitions` (Suchen Sie den Pfad zum Flash-Speicher, normalerweise ist der erste Eintrag _mmcblk0_ und entspricht dem gesamten Flash-Speicher).
* `df /data` (Ermitteln Sie die Blockgröße des Systems).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (Führen Sie dies mit den Informationen zur Blockgröße aus, die Sie gesammelt haben).

### Speicher

Verwenden Sie den Linux Memory Extractor (LiME), um Informationen zum RAM zu extrahieren. Es handelt sich um eine Kernel-Erweiterung, die über adb geladen werden sollte.

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
