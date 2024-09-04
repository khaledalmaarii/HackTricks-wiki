# Stego Tricks

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## **Data uit Lêers Onthul**

### **Binwalk**

'n Gereedskap om binêre lêers te soek na ingebedde versteekte lêers en data. Dit word geïnstalleer via `apt` en sy bron is beskikbaar op [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Herstel lêers gebaseer op hul kop- en voetstukke, nuttig vir png-prente. Geïnstalleer via `apt` met sy bron op [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Help om lêer metadata te sien, beskikbaar [hier](https://www.sno.phy.queensu.ca/\~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Soortgelyk aan exiftool, vir metadata weergawes. Installeerbaar via `apt`, bron op [GitHub](https://github.com/Exiv2/exiv2), en het 'n [amptelike webwerf](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Lêer**

Identifiseer die tipe lêer waarmee jy te doen het.

### **Strings**

Onthaal leesbare strings uit lêers, met verskeie koderinginstellings om die uitvoer te filter.
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
### **Vergelyking (cmp)**

Nuttig om 'n gewysigde lêer met sy oorspronklike weergawe wat aanlyn gevind is, te vergelyk.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Onttrek van Verborgen Gegewens in Tekst**

### **Verborgen Gegewens in Spasies**

Onsigbare karakters in blykbaar leë spasies mag inligting verberg. Om hierdie data te onttrek, besoek [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Onttrek van Gegewens uit Beelde**

### **Identifisering van Beeldbesonderhede met GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) dien om beeldlêertipes te bepaal en potensiële korrupsie te identifiseer. Voer die onderstaande opdrag uit om 'n beeld te ondersoek:
```bash
./magick identify -verbose stego.jpg
```
Om herstel op 'n beskadigde beeld te probeer, kan dit help om 'n metadata-kommentaar by te voeg:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide vir Data Versteeking**

Steghide fasiliteer die verborge van data binne `JPEG, BMP, WAV, en AU` lêers, en is in staat om versleutelde data in te sluit en uit te trek. Installasie is eenvoudig met `apt`, en sy [bronkode is beskikbaar op GitHub](https://github.com/StefanoDeVuono/steghide).

**Opdragte:**

* `steghide info file` onthul of 'n lêer verborge data bevat.
* `steghide extract -sf file [--passphrase password]` trek die verborge data uit, wagwoord is opsioneel.

Vir web-gebaseerde uittrekking, besoek [hierdie webwerf](https://futureboy.us/stegano/decinput.html).

**Bruteforce Aanval met Stegcracker:**

* Om 'n wagwoord te probeer kraak op Steghide, gebruik [stegcracker](https://github.com/Paradoxis/StegCracker.git) soos volg:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg vir PNG en BMP Lêers**

zsteg spesialiseer in die ontdekking van versteekte data in PNG en BMP lêers. Installasie word gedoen via `gem install zsteg`, met sy [bron op GitHub](https://github.com/zed-0xff/zsteg).

**Opdragte:**

* `zsteg -a file` pas alle opsporingsmetodes op 'n lêer toe.
* `zsteg -E file` spesifiseer 'n payload vir data-ekstraksie.

### **StegoVeritas en Stegsolve**

**stegoVeritas** kontroleer metadata, voer beeldtransformasies uit, en pas LSB brute forcing toe onder andere funksies. Gebruik `stegoveritas.py -h` vir 'n volledige lys van opsies en `stegoveritas.py stego.jpg` om alle kontroles uit te voer.

**Stegsolve** pas verskeie kleurfilters toe om versteekte teks of boodskappe binne beelde te onthul. Dit is beskikbaar op [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT vir Versteekte Inhoud Opsporing**

Fast Fourier Transform (FFT) tegnieke kan verborge inhoud in beelde onthul. Nuttige hulpbronne sluit in:

* [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [FFTStegPic op GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy vir Klank- en Beeldlêers**

Stegpy laat die insluiting van inligting in beeld- en klanklêers toe, wat formate soos PNG, BMP, GIF, WebP, en WAV ondersteun. Dit is beskikbaar op [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck vir PNG Lêer Analise**

Om PNG lêers te analiseer of om hul egtheid te valideer, gebruik:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Addisionele Gereedskap vir Beeldanalise**

Vir verdere verkenning, oorweeg om te besoek:

* [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
* [Beeld Foutvlak Analise](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
* [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
* [OpenStego](https://www.openstego.com/)
* [DIIT](https://diit.sourceforge.net/)

## **Data Uittrekking uit Klank**

**Klank steganografie** bied 'n unieke metode om inligting binne klanklêers te verberg. Verskeie gereedskap word gebruik om versteekte inhoud in te sluit of te onttrek.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide is 'n veelsydige gereedskap wat ontwerp is om data in JPEG, BMP, WAV, en AU-lêers te verberg. Gedetailleerde instruksies word verskaf in die [stego tricks dokumentasie](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Hierdie gereedskap is versoenbaar met 'n verskeidenheid formate, insluitend PNG, BMP, GIF, WebP, en WAV. Vir meer inligting, verwys na [Stegpy se afdeling](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg is noodsaaklik vir die beoordeling van die integriteit van klanklêers, wat gedetailleerde inligting uitlig en enige afwykings aanwys.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg presteer in die verborge en onttrekking van data binne WAV-lêers deur die minste betekenisvolle bit strategie te gebruik. Dit is beskikbaar op [GitHub](https://github.com/ragibson/Steganography#WavSteg). Opdragte sluit in:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound stel die versleuteling en opsporing van inligting binne klanklêers moontlik deur gebruik te maak van AES-256. Dit kan afgelaai word van [die amptelike bladsy](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

'n Onskatbare hulpmiddel vir visuele en analitiese inspeksie van klanklêers, Sonic Visualizer kan verborge elemente onthul wat deur ander middele onopspoorbaar is. Besoek die [amptelike webwerf](https://www.sonicvisualiser.org/) vir meer.

### **DTMF Tones - Dial Tones**

Die opsporing van DTMF-tones in klanklêers kan bereik word deur middel van aanlyn hulpmiddels soos [hierdie DTMF-detektor](https://unframework.github.io/dtmf-detect/) en [DialABC](http://dialabc.com/sound/detect/index.html).

## **Other Techniques**

### **Binary Length SQRT - QR Code**

Binaire data wat tot 'n hele getal kwadrate, mag 'n QR-kode verteenwoordig. Gebruik hierdie snit om te kontroleer:
```python
import math
math.sqrt(2500) #50
```
For binary to image conversion, check [dcode](https://www.dcode.fr/binary-image). To read QR codes, use [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Braille Vertaling**

Vir die vertaling van Braille is die [Branah Braille Translator](https://www.branah.com/braille-translator) 'n uitstekende hulpbron.

## **Verwysings**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
