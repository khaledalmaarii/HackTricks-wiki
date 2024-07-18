{% hint style="success" %}
Lernen Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
{% endhint %}


# Carving-Tools

## Autopsy

Das am häufigsten verwendete Tool in der Forensik zum Extrahieren von Dateien aus Abbildern ist [**Autopsy**](https://www.autopsy.com/download/). Laden Sie es herunter, installieren Sie es und lassen Sie es die Datei analysieren, um "versteckte" Dateien zu finden. Beachten Sie, dass Autopsy darauf ausgelegt ist, Festplattenabbilder und andere Arten von Abbildern zu unterstützen, jedoch nicht einfache Dateien.

## Binwalk <a id="binwalk"></a>

**Binwalk** ist ein Tool zum Durchsuchen binärer Dateien wie Bilder und Audiodateien nach eingebetteten Dateien und Daten.
Es kann mit `apt` installiert werden, jedoch befindet sich die [Quelle](https://github.com/ReFirmLabs/binwalk) auf Github.
**Nützliche Befehle**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Ein weiteres gängiges Tool zum Auffinden versteckter Dateien ist **foremost**. Sie können die Konfigurationsdatei von foremost in `/etc/foremost.conf` finden. Wenn Sie nur nach bestimmten Dateien suchen möchten, kommentieren Sie sie aus. Wenn Sie nichts auskommentieren, sucht foremost nach den standardmäßig konfigurierten Dateitypen.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** ist ein weiteres Tool, das verwendet werden kann, um **Dateien, die in einer Datei eingebettet sind**, zu finden und extrahieren. In diesem Fall müssen Sie die Dateitypen in der Konfigurationsdatei \(_/etc/scalpel/scalpel.conf_\) auskommentieren, die Sie extrahieren möchten.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Dieses Tool ist in Kali enthalten, aber Sie können es hier finden: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Dieses Tool kann ein Image scannen und wird **pcaps extrahieren**, **Netzwerkinformationen \(URLs, Domains, IPs, MACs, E-Mails\)** und weitere **Dateien**. Sie müssen nur Folgendes tun:
```text
bulk_extractor memory.img -o out_folder
```
Navigiere durch **alle Informationen**, die das Tool gesammelt hat \(Passwörter?\), **analysiere** die **Pakete** \(siehe [**Pcaps-Analyse**](../pcap-inspection/)\), suche nach **seltsamen Domains** \(Domains, die mit **Malware** oder **nicht existenten** verknüpft sind\).

## PhotoRec

Sie können es unter [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download) finden.

Es wird mit GUI- und CLI-Version geliefert. Sie können die **Dateitypen** auswählen, nach denen PhotoRec suchen soll.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Spezifische Daten-Carving-Tools

## FindAES

Sucht nach AES-Schlüsseln, indem es nach deren Schlüsselplänen sucht. Kann 128, 192 und 256-Bit-Schlüssel finden, wie sie von TrueCrypt und BitLocker verwendet werden.

Download [hier](https://sourceforge.net/projects/findaes/).

# Ergänzende Tools

Sie können [**viu** ](https://github.com/atanunq/viu)verwenden, um Bilder aus dem Terminal anzuzeigen.
Sie können das Linux-Befehlszeilentool **pdftotext** verwenden, um ein PDF in Text umzuwandeln und es zu lesen.



{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys einreichen.

</details>
{% endhint %}
