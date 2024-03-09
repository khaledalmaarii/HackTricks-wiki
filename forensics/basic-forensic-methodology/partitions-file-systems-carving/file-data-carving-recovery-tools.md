# Datei-/Daten-Carving & Wiederherstellungstools

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Carving & Wiederherstellungstools

Weitere Tools unter [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Das am häufigsten verwendete Tool in der Forensik zum Extrahieren von Dateien aus Abbildern ist [**Autopsy**](https://www.autopsy.com/download/). Laden Sie es herunter, installieren Sie es und lassen Sie es die Datei einlesen, um "versteckte" Dateien zu finden. Beachten Sie, dass Autopsy darauf ausgelegt ist, Festplattenabbilder und andere Arten von Abbildern zu unterstützen, jedoch nicht einfache Dateien.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ist ein Tool zur Analyse binärer Dateien, um eingebettete Inhalte zu finden. Es ist über `apt` installierbar und der Quellcode befindet sich auf [GitHub](https://github.com/ReFirmLabs/binwalk).

**Nützliche Befehle**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Ein weiteres gängiges Tool zum Auffinden versteckter Dateien ist **foremost**. Die Konfigurationsdatei von foremost befindet sich in `/etc/foremost.conf`. Wenn Sie nur nach bestimmten Dateien suchen möchten, kommentieren Sie sie aus. Wenn Sie nichts auskommentieren, sucht foremost nach den standardmäßig konfigurierten Dateitypen.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** ist ein weiteres Tool, das verwendet werden kann, um **Dateien, die in einer Datei eingebettet sind**, zu finden und extrahieren. In diesem Fall müssen Sie die Dateitypen, die extrahiert werden sollen, aus der Konfigurationsdatei (_/etc/scalpel/scalpel.conf_) auskommentieren.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Dieses Tool ist in Kali enthalten, aber Sie können es hier finden: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Dieses Tool kann ein Abbild scannen und wird **pcaps extrahieren**, darin **Netzwerkinformationen (URLs, Domains, IPs, MACs, E-Mails)** und weitere **Dateien**. Sie müssen nur Folgendes tun:
```
bulk_extractor memory.img -o out_folder
```
### PhotoRec

Sie können es unter [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download) finden.

Es gibt GUI- und CLI-Versionen. Sie können die **Dateitypen** auswählen, nach denen PhotoRec suchen soll.

![](<../../../.gitbook/assets/image (524).png>)

### binvis

Überprüfen Sie den [Code](https://code.google.com/archive/p/binvis/) und die [Webseiten-Tool](https://binvis.io/#/).

#### Funktionen von BinVis

* Visueller und aktiver **Struktur-Viewer**
* Mehrere Diagramme für verschiedene Schwerpunkte
* Fokussierung auf Teile einer Probe
* **Sehen von Zeichenfolgen und Ressourcen**, in PE- oder ELF-Dateien z. B.
* Erhalten von **Mustern** für die Kryptoanalyse von Dateien
* **Erkennen** von Packer- oder Encoder-Algorithmen
* **Identifizieren** von Steganographie durch Muster
* **Visuelles** Binär-Diffing

BinVis ist ein großartiger **Ausgangspunkt, um sich mit einem unbekannten Ziel** in einem Black-Box-Szenario vertraut zu machen.

## Spezifische Daten-Carving-Tools

### FindAES

Sucht nach AES-Schlüsseln, indem es nach deren Schlüsselplänen sucht. Kann 128, 192 und 256-Bit-Schlüssel finden, wie sie z. B. von TrueCrypt und BitLocker verwendet werden.

Download [hier](https://sourceforge.net/projects/findaes/).

## Ergänzende Tools

Sie können [**viu** ](https://github.com/atanunq/viu)verwenden, um Bilder vom Terminal aus zu sehen.\
Sie können das Linux-Befehlszeilentool **pdftotext** verwenden, um ein PDF in Text umzuwandeln und es zu lesen.
