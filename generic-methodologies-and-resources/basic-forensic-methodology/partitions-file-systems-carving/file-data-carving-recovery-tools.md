# File/Data Carving & Recovery Tools

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

## Carving & Recovery tools

Weitere Tools unter [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Das am häufigsten verwendete Tool in der Forensik zum Extrahieren von Dateien aus Bildern ist [**Autopsy**](https://www.autopsy.com/download/). Laden Sie es herunter, installieren Sie es und lassen Sie es die Datei verarbeiten, um "versteckte" Dateien zu finden. Beachten Sie, dass Autopsy entwickelt wurde, um Festplattenabbilder und andere Arten von Bildern zu unterstützen, jedoch keine einfachen Dateien.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ist ein Tool zur Analyse von Binärdateien, um eingebettete Inhalte zu finden. Es kann über `apt` installiert werden und sein Quellcode befindet sich auf [GitHub](https://github.com/ReFirmLabs/binwalk).

**Nützliche Befehle**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Ein weiteres gängiges Tool, um versteckte Dateien zu finden, ist **foremost**. Die Konfigurationsdatei von foremost befindet sich in `/etc/foremost.conf`. Wenn Sie nur nach bestimmten Dateien suchen möchten, kommentieren Sie diese aus. Wenn Sie nichts auskommentieren, sucht foremost nach den standardmäßig konfigurierten Dateitypen.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** ist ein weiteres Tool, das verwendet werden kann, um **Dateien, die in einer Datei eingebettet sind**, zu finden und zu extrahieren. In diesem Fall müssen Sie die Dateitypen, die Sie extrahieren möchten, aus der Konfigurationsdatei (_/etc/scalpel/scalpel.conf_) auskommentieren.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Dieses Tool ist in Kali enthalten, kann aber hier gefunden werden: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Dieses Tool kann ein Image scannen und wird **pcaps** darin **extrahieren**, **Netzwerkinformationen (URLs, Domains, IPs, MACs, Mails)** und weitere **Dateien**. Sie müssen nur Folgendes tun:
```
bulk_extractor memory.img -o out_folder
```
Navigieren Sie durch **alle Informationen**, die das Tool gesammelt hat (Passwörter?), **analysieren** Sie die **Pakete** (lesen Sie [**Pcaps-Analyse**](../pcap-inspection/)), suchen Sie nach **seltsamen Domains** (Domains, die mit **Malware** oder **nicht existierenden** in Verbindung stehen).

### PhotoRec

Sie finden es unter [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Es kommt mit GUI- und CLI-Versionen. Sie können die **Dateitypen** auswählen, nach denen PhotoRec suchen soll.

![](<../../../.gitbook/assets/image (242).png>)

### binvis

Überprüfen Sie den [Code](https://code.google.com/archive/p/binvis/) und die [Webseite des Tools](https://binvis.io/#/).

#### Funktionen von BinVis

* Visueller und aktiver **Struktur-Viewer**
* Mehrere Plots für verschiedene Fokuspunkte
* Fokussierung auf Teile einer Probe
* **Anzeigen von Strings und Ressourcen**, in PE- oder ELF-Executables z. B.
* Erhalten von **Mustern** für die Kryptoanalyse von Dateien
* **Erkennen** von Packer- oder Encoder-Algorithmen
* **Identifizieren** von Steganographie durch Muster
* **Visuelles** binäres Differenzieren

BinVis ist ein großartiger **Ausgangspunkt, um sich mit einem unbekannten Ziel** in einem Black-Box-Szenario vertraut zu machen.

## Spezifische Daten-Carving-Tools

### FindAES

Sucht nach AES-Schlüsseln, indem es nach ihren Schlüsselschemata sucht. In der Lage, 128, 192 und 256 Bit Schlüssel zu finden, wie sie von TrueCrypt und BitLocker verwendet werden.

Laden Sie [hier herunter](https://sourceforge.net/projects/findaes/).

## Ergänzende Tools

Sie können [**viu** ](https://github.com/atanunq/viu) verwenden, um Bilder aus dem Terminal anzuzeigen.\
Sie können das Linux-Befehlszeilen-Tool **pdftotext** verwenden, um ein PDF in Text umzuwandeln und es zu lesen.

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
