# Stego Tricks

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

## **Daten aus Dateien extrahieren**

### **Binwalk**

Ein Tool zum Suchen von Binärdateien nach eingebetteten versteckten Dateien und Daten. Es wird über `apt` installiert und der Quellcode ist auf [GitHub](https://github.com/ReFirmLabs/binwalk) verfügbar.
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Stellt Dateien basierend auf ihren Headern und Footern wieder her, nützlich für png-Bilder. Installiert über `apt` mit seiner Quelle auf [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Hilft dabei, Dateimetadaten anzuzeigen, verfügbar [hier](https://www.sno.phy.queensu.ca/\~phil/exiftool/).
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

### **Strings**

Extrahiert lesbare Zeichenfolgen aus Dateien, indem verschiedene Kodierungseinstellungen verwendet werden, um die Ausgabe zu filtern.
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
### **Comparison (cmp)**

Nützlich zum Vergleichen einer modifizierten Datei mit ihrer Originalversion, die online gefunden wurde.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Extrahieren von versteckten Daten in Text**

### **Versteckte Daten in Leerzeichen**

Unsichtbare Zeichen in scheinbar leeren Bereichen können Informationen verbergen. Um diese Daten zu extrahieren, besuchen Sie [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Daten aus Bildern extrahieren**

### **Identifizieren von Bilddetails mit GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) dient dazu, Bilddateitypen zu bestimmen und potenzielle Beschädigungen zu identifizieren. Führen Sie den folgenden Befehl aus, um ein Bild zu inspizieren:
```bash
./magick identify -verbose stego.jpg
```
Um eine beschädigte Bilddatei zu reparieren, könnte das Hinzufügen eines Metadatenkommentars hilfreich sein:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide zur Datenverbergung**

Steghide ermöglicht das Verbergen von Daten in `JPEG, BMP, WAV und AU`-Dateien und kann verschlüsselte Daten einbetten und extrahieren. Die Installation ist einfach mit `apt`, und der [Quellcode ist auf GitHub verfügbar](https://github.com/StefanoDeVuono/steghide).

**Befehle:**

* `steghide info file` zeigt an, ob eine Datei versteckte Daten enthält.
* `steghide extract -sf file [--passphrase password]` extrahiert die versteckten Daten, das Passwort ist optional.

Für die webbasierte Extraktion besuchen Sie [diese Website](https://futureboy.us/stegano/decinput.html).

**Bruteforce-Angriff mit Stegcracker:**

* Um einen Passwort-Cracking-Versuch auf Steghide durchzuführen, verwenden Sie [stegcracker](https://github.com/Paradoxis/StegCracker.git) wie folgt:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg für PNG- und BMP-Dateien**

zsteg spezialisiert sich auf das Aufdecken versteckter Daten in PNG- und BMP-Dateien. Die Installation erfolgt über `gem install zsteg`, mit [seiner Quelle auf GitHub](https://github.com/zed-0xff/zsteg).

**Befehle:**

* `zsteg -a datei` wendet alle Erkennungsmethoden auf eine Datei an.
* `zsteg -E datei` gibt eine Nutzlast für die Datenextraktion an.

### **StegoVeritas und Stegsolve**

**stegoVeritas** überprüft Metadaten, führt Bildtransformationen durch und wendet LSB-Brute-Forcing unter anderem an. Verwenden Sie `stegoveritas.py -h` für eine vollständige Liste der Optionen und `stegoveritas.py stego.jpg`, um alle Überprüfungen auszuführen.

**Stegsolve** wendet verschiedene Farbfilter an, um versteckte Texte oder Nachrichten in Bildern zu enthüllen. Es ist auf [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve) verfügbar.

### **FFT zur Erkennung versteckter Inhalte**

Fast Fourier Transform (FFT)-Techniken können verborgene Inhalte in Bildern aufdecken. Nützliche Ressourcen sind:

* [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [FFTStegPic auf GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy für Audio- und Bilddateien**

Stegpy ermöglicht das Einbetten von Informationen in Bild- und Audiodateien und unterstützt Formate wie PNG, BMP, GIF, WebP und WAV. Es ist auf [GitHub](https://github.com/dhsdshdhk/stegpy) verfügbar.

### **Pngcheck zur Analyse von PNG-Dateien**

Um PNG-Dateien zu analysieren oder ihre Authentizität zu überprüfen, verwenden Sie:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Zusätzliche Werkzeuge zur Bildanalyse**

Für weitere Erkundungen sollten Sie folgende Seiten besuchen:

* [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
* [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
* [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
* [OpenStego](https://www.openstego.com/)
* [DIIT](https://diit.sourceforge.net/)

## **Daten aus Audios extrahieren**

**Audio-Steganographie** bietet eine einzigartige Methode, Informationen in Audiodateien zu verbergen. Verschiedene Werkzeuge werden verwendet, um versteckte Inhalte einzubetten oder abzurufen.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide ist ein vielseitiges Werkzeug, das zum Verstecken von Daten in JPEG-, BMP-, WAV- und AU-Dateien entwickelt wurde. Detaillierte Anweisungen finden Sie in der [Stego-Tricks-Dokumentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Dieses Werkzeug ist mit einer Vielzahl von Formaten kompatibel, darunter PNG, BMP, GIF, WebP und WAV. Für weitere Informationen siehe den [Stegpy-Bereich](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg ist entscheidend für die Bewertung der Integrität von Audiodateien, hebt detaillierte Informationen hervor und identifiziert etwaige Abweichungen.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg zeichnet sich darin aus, Daten innerhalb von WAV-Dateien mithilfe der Strategie des am wenigsten signifikanten Bits zu verbergen und zu extrahieren. Es ist auf [GitHub](https://github.com/ragibson/Steganography#WavSteg) verfügbar. Befehle umfassen:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound ermöglicht die Verschlüsselung und Erkennung von Informationen in Audiodateien mithilfe von AES-256. Es kann von [der offiziellen Seite](http://jpinsoft.net/deepsound/download.aspx) heruntergeladen werden.

### **Sonic Visualizer**

Ein unverzichtbares Werkzeug für die visuelle und analytische Inspektion von Audiodateien, Sonic Visualizer kann versteckte Elemente aufdecken, die mit anderen Mitteln nicht erkennbar sind. Besuchen Sie die [offizielle Website](https://www.sonicvisualiser.org/) für mehr.

### **DTMF Töne - Wähltöne**

Die Erkennung von DTMF-Tönen in Audiodateien kann durch Online-Tools wie [diesen DTMF-Detektor](https://unframework.github.io/dtmf-detect/) und [DialABC](http://dialabc.com/sound/detect/index.html) erreicht werden.

## **Andere Techniken**

### **Binäre Länge SQRT - QR-Code**

Binäre Daten, die zu einer ganzen Zahl quadrieren, könnten einen QR-Code darstellen. Verwenden Sie diesen Code-Schnipsel zur Überprüfung:
```python
import math
math.sqrt(2500) #50
```
Für die Umwandlung von Binärdaten in Bilder, überprüfen Sie [dcode](https://www.dcode.fr/binary-image). Um QR-Codes zu lesen, verwenden Sie [diesen Online-Barcode-Reader](https://online-barcode-reader.inliteresearch.com/).

### **Braille-Übersetzung**

Für die Übersetzung von Braille ist der [Branah Braille Translator](https://www.branah.com/braille-translator) eine ausgezeichnete Ressource.

## **Referenzen**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

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
