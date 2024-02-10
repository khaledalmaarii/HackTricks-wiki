# Stego-Tricks

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories** senden.

</details>

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Schwachstellen, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm_source=referral&utm_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Extrahieren von Daten aus Dateien**

### **Binwalk**
Ein Tool zum Suchen von Binärdateien nach eingebetteten versteckten Dateien und Daten. Es wird über `apt` installiert und der Quellcode ist auf [GitHub](https://github.com/ReFirmLabs/binwalk) verfügbar.
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**
Stellt Dateien anhand ihrer Header und Footer wieder her, nützlich für PNG-Bilder. Über `apt` installiert, mit Quellcode auf [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**
Hilft dabei, Metadaten von Dateien anzuzeigen, verfügbar [hier](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**
Ähnlich wie exiftool, zur Anzeige von Metadaten. Installierbar über `apt`, Quellcode auf [GitHub](https://github.com/Exiv2/exiv2) und hat eine [offizielle Website](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Datei**
Identifizieren Sie den Dateityp, mit dem Sie es zu tun haben.

### **Zeichenketten**
Extrahiert lesbare Zeichenketten aus Dateien und verwendet verschiedene Codierungseinstellungen, um die Ausgabe zu filtern.
```bash
strings -n 6 file # Extracts strings with a minimum length of 6
strings -n 6 file | head -n 20 # First 20 strings
strings -n 6 file | tail -n 20 # Last 20 strings
strings -e s -n 6 file # 7bit strings
strings -e S -n 6 file # 8bit strings
strings -e l -n 6 file # 16bit strings (little-endian)
strings -e b -n 6 file # 16bit strings (big-endian)
strings -e L -n 6 file # 32bit strings (little-endian)
strings -e B -n 6 file # 32bit strings (big-endian)
```
### **Vergleich (cmp)**
Nützlich zum Vergleichen einer modifizierten Datei mit ihrer ursprünglichen Version, die online gefunden wurde.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Extrahieren versteckter Daten in Text**

### **Versteckte Daten in Leerzeichen**
Unsichtbare Zeichen in scheinbar leeren Leerzeichen können Informationen verbergen. Um diese Daten zu extrahieren, besuchen Sie [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).



***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

## **Extrahieren von Daten aus Bildern**

### **Erkennen von Bilddetails mit GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) dient dazu, Bilddateitypen zu bestimmen und potenzielle Korruptionen zu identifizieren. Führen Sie den folgenden Befehl aus, um ein Bild zu inspizieren:
```bash
./magick identify -verbose stego.jpg
```
Um eine beschädigte Bilddatei zu reparieren, kann das Hinzufügen eines Metadatenkommentars hilfreich sein:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide zur Datenverdeckung**

Steghide ermöglicht das Verstecken von Daten in `JPEG-, BMP-, WAV- und AU-Dateien` und kann verschlüsselte Daten einbetten und extrahieren. Die Installation ist einfach über `apt` möglich und der [Quellcode ist auf GitHub verfügbar](https://github.com/StefanoDeVuono/steghide).

**Befehle:**
- `steghide info file` zeigt an, ob eine Datei versteckte Daten enthält.
- `steghide extract -sf file [--passphrase password]` extrahiert die versteckten Daten, Passwort optional.

Für die webbasierte Extraktion besuchen Sie [diese Website](https://futureboy.us/stegano/decinput.html).

**Brute-Force-Angriff mit Stegcracker:**
- Um ein Passwortknacken mit Steghide zu versuchen, verwenden Sie [stegcracker](https://github.com/Paradoxis/StegCracker.git) wie folgt:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg für PNG- und BMP-Dateien**

zsteg ist spezialisiert auf das Aufdecken versteckter Daten in PNG- und BMP-Dateien. Die Installation erfolgt über `gem install zsteg`, mit dem [Quellcode auf GitHub](https://github.com/zed-0xff/zsteg).

**Befehle:**
- `zsteg -a Datei` wendet alle Erkennungsmethoden auf eine Datei an.
- `zsteg -E Datei` gibt eine Nutzlast für die Datenextraktion an.

### **StegoVeritas und Stegsolve**

**stegoVeritas** überprüft Metadaten, führt Bildtransformationen durch und wendet unter anderem LSB-Brute-Force an. Verwenden Sie `stegoveritas.py -h`, um eine vollständige Liste der Optionen anzuzeigen, und `stegoveritas.py stego.jpg`, um alle Überprüfungen auszuführen.

**Stegsolve** wendet verschiedene Farbfilter an, um versteckte Texte oder Nachrichten in Bildern sichtbar zu machen. Es ist auf [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve) verfügbar.

### **FFT zur Erkennung versteckter Inhalte**

Techniken der schnellen Fourier-Transformation (FFT) können verborgene Inhalte in Bildern aufdecken. Nützliche Ressourcen sind:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic auf GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy für Audio- und Bilddateien**

Stegpy ermöglicht das Einbetten von Informationen in Bild- und Audiodateien und unterstützt Formate wie PNG, BMP, GIF, WebP und WAV. Es ist auf [GitHub](https://github.com/dhsdshdhk/stegpy) verfügbar.

### **Pngcheck zur Analyse von PNG-Dateien**

Um PNG-Dateien zu analysieren oder ihre Echtheit zu überprüfen, verwenden Sie:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Zusätzliche Tools zur Bildanalyse**

Für weitere Erkundungen empfehlen wir:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **Extrahieren von Daten aus Audiodateien**

**Audio-Steganographie** bietet eine einzigartige Methode, um Informationen in Audiodateien zu verbergen. Verschiedene Tools werden verwendet, um versteckte Inhalte einzubetten oder abzurufen.

### **Steghide (JPEG, BMP, WAV, AU)**
Steghide ist ein vielseitiges Tool, das entwickelt wurde, um Daten in JPEG-, BMP-, WAV- und AU-Dateien zu verstecken. Detaillierte Anweisungen finden Sie in der [Dokumentation zu Stego-Tricks](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**
Dieses Tool ist mit einer Vielzahl von Formaten kompatibel, darunter PNG, BMP, GIF, WebP und WAV. Weitere Informationen finden Sie im Abschnitt [Stegpy](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**
ffmpeg ist entscheidend für die Bewertung der Integrität von Audiodateien, die Hervorhebung detaillierter Informationen und die Identifizierung von Abweichungen.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**
WavSteg ist besonders gut darin, Daten in WAV-Dateien mithilfe der Least Significant Bit-Strategie zu verbergen und zu extrahieren. Es ist auf [GitHub](https://github.com/ragibson/Steganography#WavSteg) verfügbar. Die Befehle umfassen:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**
Deepsound ermöglicht die Verschlüsselung und Erkennung von Informationen in Audiodateien mithilfe von AES-256. Es kann von [der offiziellen Seite](http://jpinsoft.net/deepsound/download.aspx) heruntergeladen werden.

### **Sonic Visualizer**
Ein unverzichtbares Werkzeug zur visuellen und analytischen Inspektion von Audiodateien, Sonic Visualizer kann versteckte Elemente aufdecken, die auf andere Weise nicht erkennbar sind. Besuchen Sie die [offizielle Website](https://www.sonicvisualiser.org/) für weitere Informationen.

### **DTMF-Töne - Wähltöne**
Die Erkennung von DTMF-Tönen in Audiodateien kann mithilfe von Online-Tools wie [diesem DTMF-Detektor](https://unframework.github.io/dtmf-detect/) und [DialABC](http://dialabc.com/sound/detect/index.html) erreicht werden.

## **Andere Techniken**

### **Binäre Länge SQRT - QR-Code**
Binäre Daten, die zu einer ganzen Zahl quadriert werden, könnten einen QR-Code darstellen. Verwenden Sie diesen Codeausschnitt, um dies zu überprüfen:
```python
import math
math.sqrt(2500) #50
```
Für die Umwandlung von Binärdateien in Bilder können Sie [dcode](https://www.dcode.fr/binary-image) verwenden. Um QR-Codes zu lesen, nutzen Sie [diesen Online-Barcode-Reader](https://online-barcode-reader.inliteresearch.com/).

### **Braille-Übersetzung**
Für die Übersetzung von Braille ist der [Branah Braille-Übersetzer](https://www.branah.com/braille-translator) eine ausgezeichnete Ressource.

## **Referenzen**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Schwachstellen, damit Sie sie schneller beheben können. Intruder überwacht Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie Pull Requests an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
