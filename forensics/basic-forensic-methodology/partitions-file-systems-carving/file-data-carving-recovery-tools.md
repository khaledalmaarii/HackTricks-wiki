<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Schwachstellen, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

# Carving & Recovery-Tools

Weitere Tools unter [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

## Autopsy

Das am häufigsten verwendete Tool in der Forensik zum Extrahieren von Dateien aus Abbildungen ist [**Autopsy**](https://www.autopsy.com/download/). Laden Sie es herunter, installieren Sie es und lassen Sie es die Datei einlesen, um "versteckte" Dateien zu finden. Beachten Sie, dass Autopsy für die Unterstützung von Festplattenabbildern und anderen Arten von Abbildungen entwickelt wurde, nicht jedoch für einfache Dateien.

## Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ist ein Tool zur Analyse von Binärdateien, um eingebettete Inhalte zu finden. Es kann über `apt` installiert werden und der Quellcode befindet sich auf [GitHub](https://github.com/ReFirmLabs/binwalk).

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

**Scalpel** ist ein weiteres Tool, das verwendet werden kann, um **in einer Datei eingebettete Dateien** zu finden und zu extrahieren. In diesem Fall müssen Sie die Dateitypen, die Sie extrahieren möchten, aus der Konfigurationsdatei (_/etc/scalpel/scalpel.conf_) auskommentieren.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Dieses Tool ist in Kali enthalten, aber Sie können es hier finden: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Dieses Tool kann ein Image scannen und **pcaps**, **Netzwerkinformationen (URLs, Domains, IPs, MACs, E-Mails)** und weitere **Dateien** extrahieren. Sie müssen nur Folgendes tun:
```
bulk_extractor memory.img -o out_folder
```
Navigieren Sie durch **alle Informationen**, die das Tool gesammelt hat (Passwörter?), **analysieren** Sie die **Pakete** (lesen Sie [**Pcaps-Analyse**](../pcap-inspection/)), suchen Sie nach **seltsamen Domains** (Domains im Zusammenhang mit **Malware** oder **nicht existenten**).

## PhotoRec

Sie finden es unter [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Es gibt GUI- und CLI-Versionen. Sie können die **Dateitypen** auswählen, nach denen PhotoRec suchen soll.

![](<../../../.gitbook/assets/image (524).png>)

## binvis

Überprüfen Sie den [Code](https://code.google.com/archive/p/binvis/) und das [Webseiten-Tool](https://binvis.io/#/).

### Funktionen von BinVis

* Visueller und aktiver **Strukturviewer**
* Mehrere Diagramme für verschiedene Fokuspunkte
* Fokussierung auf Teile einer Probe
* **Anzeigen von Zeichenketten und Ressourcen**, z. B. in PE- oder ELF-Dateien
* Erhalten von **Mustern** für die Kryptanalyse von Dateien
* **Erkennen** von Packer- oder Encoder-Algorithmen
* **Erkennen** von Steganographie anhand von Mustern
* **Visueller** Binärvergleich

BinVis ist ein guter **Ausgangspunkt, um sich mit einem unbekannten Ziel** in einem Black-Box-Szenario vertraut zu machen.

# Spezifische Datenwiederherstellungstools

## FindAES

Sucht nach AES-Schlüsseln, indem es nach ihren Schlüsselplänen sucht. Kann 128-, 192- und 256-Bit-Schlüssel finden, wie sie von TrueCrypt und BitLocker verwendet werden.

Hier herunterladen: [here](https://sourceforge.net/projects/findaes/).

# Ergänzende Tools

Sie können [**viu** ](https://github.com/atanunq/viu)verwenden, um Bilder vom Terminal aus anzuzeigen.\
Sie können das Linux-Befehlszeilentool **pdftotext** verwenden, um ein PDF in Text umzuwandeln und es zu lesen.


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Schwachstellen, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder folgen Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
