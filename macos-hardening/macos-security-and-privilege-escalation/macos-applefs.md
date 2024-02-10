# macOS AppleFS

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Apple Proprietäres Dateisystem (APFS)

**Apple File System (APFS)** ist ein modernes Dateisystem, das das Hierarchical File System Plus (HFS+) ablösen soll. Die Entwicklung wurde durch die Notwendigkeit von **verbesserter Leistung, Sicherheit und Effizienz** vorangetrieben.

Einige bemerkenswerte Funktionen von APFS sind:

1. **Platzfreigabe**: APFS ermöglicht es mehreren Volumes, **den gleichen zugrunde liegenden freien Speicher** auf einem einzelnen physischen Gerät zu teilen. Dadurch wird eine effizientere Nutzung des Speicherplatzes ermöglicht, da die Volumes dynamisch wachsen und schrumpfen können, ohne dass eine manuelle Größenänderung oder Neupartitionierung erforderlich ist.
1. Dies bedeutet im Vergleich zu herkömmlichen Partitionen auf Dateiplatten, **dass in APFS verschiedene Partitionen (Volumes) den gesamten Festplattenspeicher teilen**, während eine reguläre Partition normalerweise eine feste Größe hatte.
2. **Snapshots**: APFS unterstützt das **Erstellen von Snapshots**, die **schreibgeschützte**, zeitpunktbezogene Instanzen des Dateisystems sind. Snapshots ermöglichen effiziente Backups und einfache Systemrücksetzungen, da sie minimalen zusätzlichen Speicherplatz verbrauchen und schnell erstellt oder zurückgesetzt werden können.
3. **Klone**: APFS kann **Datei- oder Verzeichnisklone erstellen, die den gleichen Speicherplatz** wie das Original teilen, bis entweder der Klon oder die Originaldatei geändert wird. Diese Funktion bietet eine effiziente Möglichkeit, Kopien von Dateien oder Verzeichnissen zu erstellen, ohne den Speicherplatz zu duplizieren.
4. **Verschlüsselung**: APFS unterstützt **native Vollplattenverschlüsselung** sowie Datei- und Verzeichnisverschlüsselung, um die Datensicherheit in verschiedenen Anwendungsfällen zu verbessern.
5. **Absturzsicherung**: APFS verwendet ein **Kopieren-beim-Schreiben-Metadatenschema, das die Konsistenz des Dateisystems auch bei plötzlichem Stromausfall oder Systemabsturz gewährleistet**, um das Risiko von Datenkorruption zu reduzieren.

Insgesamt bietet APFS ein moderneres, flexibleres und effizienteres Dateisystem für Apple-Geräte mit Schwerpunkt auf verbesserter Leistung, Zuverlässigkeit und Sicherheit.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Das `Data`-Volume ist unter **`/System/Volumes/Data`** eingebunden (Sie können dies mit `diskutil apfs list` überprüfen).

Die Liste der Firmlinks befindet sich in der Datei **`/usr/share/firmlinks`**.
```bash
cat /usr/share/firmlinks
/AppleInternal	AppleInternal
/Applications	Applications
/Library	Library
[...]
```
Auf der **linken Seite** befindet sich der Verzeichnispfad auf dem **Systemvolume**, und auf der **rechten Seite** der Verzeichnispfad, auf dem es auf dem **Datenvolume** abgebildet wird. Also `/library` --> `/system/Volumes/data/library`

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
