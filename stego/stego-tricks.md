# Stego Truuks

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## **Data Uithaal uit Lêers**

### **Binwalk**

'n Gereedskap om binêre lêers te soek vir ingeslote verborge lêers en data. Dit word geïnstalleer via `apt` en sy bron is beskikbaar op [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Herstel lêers gebaseer op hul kop-en-staart-inligting, nuttig vir png-beelde. Geïnstalleer via `apt` met sy bron op [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Helps to view file metadata, beskikbaar [hier](https://www.sno.phy.queensu.ca/\~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Soortgelyk aan exiftool, vir metadatabesoek. Installeerbaar via `apt`, bron op [GitHub](https://github.com/Exiv2/exiv2), en het 'n [amptelike webwerf](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Lêer**

Identifiseer die tipe lêer waarmee jy werk.

### **Strings**

Onttrek leesbare strings uit lêers, deur verskeie enkoderingsinstellings te gebruik om die uitset te filter.
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

Nuttig vir die vergelyking van 'n gewysigde lêer met sy oorspronklike weergawe wat aanlyn gevind is.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Uithaling van Versteekte Data in Teks**

### **Versteekte Data in Spasies**

Onsigbare karakters in ogenschijnlik leë spasies kan inligting verberg. Om hierdie data te onttrek, besoek [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Uithaling van Data uit Beelde**

### **Identifisering van Beelddetails met GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) dien om beeldlêertipes te bepaal en potensiële korruptie te identifiseer. Voer die onderstaande bevel uit om 'n beeld te inspekteer:
```bash
./magick identify -verbose stego.jpg
```
Om 'n beskadigde beeld te probeer herstel, kan dit help om 'n metadata opmerking by te voeg:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide vir Data Versteek**

Steghide fasiliteer die versteek van data binne `JPEG, BMP, WAV, en AU` lêers, in staat om versleutelde data in te bed en te onttrek. Installasie is maklik met behulp van `apt`, en sy [bronkode is beskikbaar op GitHub](https://github.com/StefanoDeVuono/steghide).

**Opdragte:**

* `steghide info lêer` onthul of 'n lêer verskuilde data bevat.
* `steghide extract -sf lêer [--wagwoord wagwoord]` onttrek die verskuilde data, wagwoord is opsioneel.

Vir web-gebaseerde onttrekking, besoek [hierdie webwerf](https://futureboy.us/stegano/decinput.html).

**Bruteforce Aanval met Stegcracker:**

* Om wagwoordkraakpogings op Steghide te doen, gebruik [stegcracker](https://github.com/Paradoxis/StegCracker.git) soos volg:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg vir PNG en BMP-lêers**

zsteg spesialiseer daarin om verskuilde data in PNG- en BMP-lêers bloot te lê. Installasie word gedoen deur `gem install zsteg`, met sy [bron op GitHub](https://github.com/zed-0xff/zsteg).

**Opdragte:**

* `zsteg -a lêer` pas alle opsporingmetodes op 'n lêer toe.
* `zsteg -E lêer` spesifiseer 'n nuttelading vir data-ekstraksie.

### **StegoVeritas en Stegsolve**

**stegoVeritas** ondersoek metadata, voer beeldtransformasies uit, en pas LSB-brute forcing onder andere kenmerke toe. Gebruik `stegoveritas.py -h` vir 'n volledige lys van opsies en `stegoveritas.py stego.jpg` om alle kontroles uit te voer.

**Stegsolve** pas verskeie kleurfilters toe om verskuilde teks of boodskappe binne beelde te onthul. Dit is beskikbaar op [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT vir Verskuilde Inhoudsopsporing**

Fast Fourier Transform (FFT) tegnieke kan verskuilde inhoud in beelde onthul. Nuttige bronne sluit in:

* [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [FFTStegPic op GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy vir Klank- en Beeldlêers**

Stegpy maak dit moontlik om inligting in beeld- en klanklêers in te bed, met ondersteuning vir formate soos PNG, BMP, GIF, WebP, en WAV. Dit is beskikbaar op [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck vir PNG-lêerontleding**

Om PNG-lêers te ontleed of hul egtheid te valideer, gebruik:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Addisionele Gereedskap vir Beeldanalise**

Vir verdere verkenning, oorweeg om die volgende webwerwe te besoek:

* [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
* [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
* [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
* [OpenStego](https://www.openstego.com/)
* [DIIT](https://diit.sourceforge.net/)

## **Data Uithaal uit Klanklêers**

**Klanksteganografie** bied 'n unieke metode om inligting binne klanklêers te verberg. Verskeie gereedskap word gebruik vir die inbedding of herwinning van verborge inhoud.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide is 'n veelsydige gereedskap wat ontwerp is om data in JPEG, BMP, WAV, en AU lêers te verberg. Gedetailleerde instruksies word verskaf in die [stego tricks dokumentasie](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Hierdie gereedskap is verenigbaar met 'n verskeidenheid formate, insluitend PNG, BMP, GIF, WebP, en WAV. Vir meer inligting, verwys na [Stegpy se afdeling](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg is noodsaaklik vir die assessering van die integriteit van klanklêers, waarby gedetailleerde inligting uitgelig word en enige teenstrydighede aangedui word.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg blink uit in die verberging en onttrekking van data binne WAV-lêers deur die gebruik van die minst beduidende bit-strategie. Dit is toeganklik op [GitHub](https://github.com/ragibson/Steganography#WavSteg). Opdragte sluit in:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound maak dit moontlik om inligting binne klanklêers te enkripteer en op te spoor met behulp van AES-256. Dit kan afgelaai word vanaf [die amptelike bladsy](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

'n Onbetaalbare instrument vir visuele en analitiese inspeksie van klanklêers, Sonic Visualizer kan verborge elemente onthul wat nie deur ander metodes opgespoor kan word nie. Besoek die [ampstelike webwerf](https://www.sonicvisualiser.org/) vir meer inligting.

### **DTMF-tone - Kies-tone**

Die opsporing van DTMF-tone in klanklêers kan bereik word deur aanlyn gereedskap soos [hierdie DTMF-detektor](https://unframework.github.io/dtmf-detect/) en [DialABC](http://dialabc.com/sound/detect/index.html).

## **Ander Tegnieke**

### **Binêre Lengte SQRT - QR-kode**

Binêre data wat tot 'n heelgetal kwadreer, kan 'n QR-kode verteenwoordig. Gebruik hierdie snipper om te kontroleer:
```python
import math
math.sqrt(2500) #50
```
### **Braille Vertaling**

Vir die vertaling van Braille, is die [Branah Braille Translator](https://www.branah.com/braille-translator) 'n uitstekende bron.

## **Verwysings**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
