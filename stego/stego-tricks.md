# Stego Truuks

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy hulle vinniger kan regstel. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Data Uithaal uit Lêers**

### **Binwalk**
'n Hulpmiddel om binêre lêers te soek vir ingebedde verskuilde lêers en data. Dit word geïnstalleer via `apt` en die bron is beskikbaar op [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**
Herstel lêers gebaseer op hul kop- en voetskrifte, nuttig vir png-beelde. Geïnstalleer via `apt` met sy bron op [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**
Helps om lêermetadata te sien, beskikbaar [hier](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**
Soortgelyk aan exiftool, vir metadata-siening. Installeerbaar via `apt`, bron op [GitHub](https://github.com/Exiv2/exiv2), en het 'n [amptelike webwerf](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Lêer**
Identifiseer die tipe lêer waarmee jy werk.

### **Strings**
Onttrek leesbare strings uit lêers deur verskillende enkoderingsinstellings te gebruik om die uitset te filter.
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
Onsigbare karakters in ogieskynlik leë spasies kan inligting versteek. Om hierdie data uit te haal, besoek [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).



***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik **werkstrome** te bou en outomatiseer met behulp van die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry Vandag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

## **Uithaling van Data uit Beelde**

### **Identifiseer Beelddetails met GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) dien om beeldlêertipes te bepaal en potensiële korruptie te identifiseer. Voer die volgende bevel uit om 'n beeld te ondersoek:
```bash
./magick identify -verbose stego.jpg
```
Om 'n beskadigde prent te probeer herstel, kan dit help om 'n metadata-opmerking by te voeg:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide vir Data Versteek**

Steghide maak dit maklik om data binne `JPEG, BMP, WAV, en AU` lêers te versteek, en is in staat om versleutelde data in te bed en te onttrek. Die installasie is eenvoudig met behulp van `apt`, en die [bronkode is beskikbaar op GitHub](https://github.com/StefanoDeVuono/steghide).

**Opdragte:**
- `steghide info lêer` onthul of 'n lêer versteekte data bevat.
- `steghide extract -sf lêer [--passphrase wagwoord]` onttrek die versteekte data, wagwoord is opsioneel.

Vir web-gebaseerde onttrekking, besoek [hierdie webwerf](https://futureboy.us/stegano/decinput.html).

**Bruteforce Aanval met Stegcracker:**
- Om wagwoordkraking op Steghide te probeer, gebruik [stegcracker](https://github.com/Paradoxis/StegCracker.git) soos volg:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg vir PNG- en BMP-lêers**

zsteg spesialiseer in die ontdekking van verborge data in PNG- en BMP-lêers. Installasie word gedoen deur `gem install zsteg`, met die [bron op GitHub](https://github.com/zed-0xff/zsteg).

**Opdragte:**
- `zsteg -a lêer` pas alle opsporingsmetodes toe op 'n lêer.
- `zsteg -E lêer` spesifiseer 'n nutslading vir data-onttrekking.

### **StegoVeritas en Stegsolve**

**stegoVeritas** kontroleer metadata, voer beeldtransformasies uit en pas LSB-brute force toe, onder andere funksies. Gebruik `stegoveritas.py -h` vir 'n volledige lys van opsies en `stegoveritas.py stego.jpg` om alle kontroles uit te voer.

**Stegsolve** pas verskillende kleurfilters toe om verborge teks of boodskappe binne beelde te onthul. Dit is beskikbaar op [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT vir Ontdekking van Versteekte Inhoud**

Fast Fourier Transform (FFT) tegnieke kan verborge inhoud in beelde onthul. Nuttige bronne sluit in:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic op GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy vir Klank- en Beeldlêers**

Stegpy maak dit moontlik om inligting in beeld- en klanklêers in te bed, met ondersteuning vir formate soos PNG, BMP, GIF, WebP en WAV. Dit is beskikbaar op [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck vir PNG-lêeranalise**

Om PNG-lêers te analiseer of hul egtheid te bevestig, gebruik:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Addisionele Gereedskap vir Beeldanalise**

Vir verdere verkenning, oorweeg om die volgende webwerwe te besoek:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **Data Onttrekking uit Klanklêers**

**Klank steganografie** bied 'n unieke metode om inligting binne klanklêers te versteek. Verskillende gereedskap word gebruik vir die inbedding of herwinning van verborge inhoud.

### **Steghide (JPEG, BMP, WAV, AU)**
Steghide is 'n veelsydige gereedskap wat ontwerp is om data in JPEG, BMP, WAV en AU lêers te versteek. Gedetailleerde instruksies word verskaf in die [stego tricks dokumentasie](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**
Hierdie gereedskap is versoenbaar met 'n verskeidenheid formate, insluitend PNG, BMP, GIF, WebP en WAV. Vir meer inligting, verwys na [Stegpy se afdeling](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**
ffmpeg is noodsaaklik vir die assessering van die integriteit van klanklêers, waarby gedetailleerde inligting beklemtoon word en enige afwykings uitgewys word.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**
WavSteg blink uit in die versteek en onttrek van data binne WAV-lêers deur die minst betekenisvolle bit-strategie te gebruik. Dit is toeganklik op [GitHub](https://github.com/ragibson/Steganography#WavSteg). Opdragte sluit in:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**
Deepsound maak dit moontlik om inligting binne klanklêers te versleutel en op te spoor deur gebruik te maak van AES-256. Dit kan afgelaai word vanaf [die amptelike bladsy](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**
'n Onvervangbare instrument vir visuele en analitiese inspeksie van klanklêers, Sonic Visualizer kan verborge elemente onthul wat deur ander metodes nie opgespoor kan word nie. Besoek die [amptelike webwerf](https://www.sonicvisualiser.org/) vir meer inligting.

### **DTMF-tone - Kies-tone**
Die opsporing van DTMF-tone in klanklêers kan bereik word deur aanlyn hulpmiddels soos [hierdie DTMF-opsporing](https://unframework.github.io/dtmf-detect/) en [DialABC](http://dialabc.com/sound/detect/index.html) te gebruik.

## **Ander Tegnieke**

### **Binêre Lengte SQRT - QR-kode**
Binêre data wat 'n heelgetal gee wanneer dit vierkant gemaak word, kan 'n QR-kode verteenwoordig. Gebruik hierdie snipper om te kontroleer:
```python
import math
math.sqrt(2500) #50
```
Vir binêre na beeld omskakeling, kyk na [dcode](https://www.dcode.fr/binary-image). Gebruik [hierdie aanlyn barkodeleser](https://online-barcode-reader.inliteresearch.com/) om QR-kodes te lees.

### **Braille-vertaling**
Vir die vertaling van Braille, is die [Branah Braille Translator](https://www.branah.com/braille-translator) 'n uitstekende bron.

## **Verwysings**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy dit vinniger kan regmaak. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
