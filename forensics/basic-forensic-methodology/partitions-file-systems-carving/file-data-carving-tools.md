<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


# Carving-Tools

## Autopsy

Das am häufigsten verwendete Tool in der Forensik zur Extraktion von Dateien aus Abbildungen ist [**Autopsy**](https://www.autopsy.com/download/). Laden Sie es herunter, installieren Sie es und lassen Sie es die Datei einlesen, um "versteckte" Dateien zu finden. Beachten Sie, dass Autopsy für die Unterstützung von Festplattenabbildern und anderen Arten von Abbildungen entwickelt wurde, nicht jedoch für einfache Dateien.

## Binwalk <a id="binwalk"></a>

**Binwalk** ist ein Tool zum Suchen von Binärdateien wie Abbildungen und Audiodateien nach eingebetteten Dateien und Daten.
Es kann mit `apt` installiert werden, jedoch befindet sich die [Quelle](https://github.com/ReFirmLabs/binwalk) auf GitHub.
**Nützliche Befehle**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Ein weiteres gängiges Tool zum Auffinden versteckter Dateien ist **foremost**. Die Konfigurationsdatei von foremost befindet sich in `/etc/foremost.conf`. Wenn Sie nur nach bestimmten Dateien suchen möchten, entfernen Sie die Kommentarzeichen. Wenn Sie nichts kommentieren, sucht foremost nach den standardmäßig konfigurierten Dateitypen.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** ist ein weiteres Tool, das verwendet werden kann, um **in einer Datei eingebettete Dateien** zu finden und extrahieren. In diesem Fall müssen Sie die Dateitypen, die Sie extrahieren möchten, aus der Konfigurationsdatei \(_/etc/scalpel/scalpel.conf_\) auskommentieren.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Dieses Tool ist in Kali enthalten, aber Sie können es hier finden: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Dieses Tool kann ein Image scannen und **pcaps extrahieren**, **Netzwerkinformationen (URLs, Domains, IPs, MACs, E-Mails)** und weitere **Dateien**. Sie müssen nur Folgendes tun:
```text
bulk_extractor memory.img -o out_folder
```
Durchsuchen Sie **alle Informationen**, die das Tool gesammelt hat \(Passwörter?\), **analysieren** Sie die **Pakete** \(lesen Sie [**Pcaps-Analyse**](../pcap-inspection/)\), suchen Sie nach **seltsamen Domains** \(Domains im Zusammenhang mit **Malware** oder **nicht existenten**\).

## PhotoRec

Sie finden es unter [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Es gibt eine GUI- und eine CLI-Version. Sie können die **Dateitypen** auswählen, nach denen PhotoRec suchen soll.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Spezifische Daten-Carving-Tools

## FindAES

Sucht nach AES-Schlüsseln, indem es nach ihren Schlüsselplänen sucht. Kann 128, 192 und 256-Bit-Schlüssel finden, wie sie von TrueCrypt und BitLocker verwendet werden.

Hier herunterladen: [here](https://sourceforge.net/projects/findaes/).

# Ergänzende Tools

Sie können [**viu** ](https://github.com/atanunq/viu)verwenden, um Bilder in der Konsole anzuzeigen.
Sie können das Linux-Befehlszeilentool **pdftotext** verwenden, um ein PDF in Text umzuwandeln und es zu lesen.



<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repos senden.

</details>
