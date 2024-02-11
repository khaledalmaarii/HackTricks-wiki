# Mbinu za Stego

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pata udhaifu unaofaa zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho wa kujitokeza, inapata masuala katika mfumo wako mzima wa teknolojia, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Kuchota Data kutoka kwenye Faili**

### **Binwalk**
Zana ya kutafuta faili za binary kwa faili na data iliyofichwa. Inasakinishwa kupitia `apt` na chanzo chake kinapatikana kwenye [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**
Inarejesha faili kulingana na vichwa vyao na miguu, inafaa kwa picha za png. Imewekwa kupitia `apt` na chanzo chake kwenye [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**
Inasaidia kuangalia metadata ya faili, inapatikana [hapa](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**
Kama vile exiftool, kwa kuangalia metadata. Inaweza kusakinishwa kupitia `apt`, chanzo kwenye [GitHub](https://github.com/Exiv2/exiv2), na ina [tovuti rasmi](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Faili**
Tambua aina ya faili unayoshughulika nayo.

### **Vidokezo**
Chambua herufi zinazoweza kusomwa kutoka kwenye faili, ukitumia mipangilio mbalimbali ya uendeshaji ili kuchuja matokeo.
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
### **Ulinganisho (cmp)**
Inatumika kulinganisha faili iliyobadilishwa na toleo lake la awali lililopatikana mtandaoni.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Kuchimbua Data Iliyofichwa katika Matini**

### **Data Iliyofichwa katika Nafasi**
Vipengele visivyoonekana katika nafasi zisizo na maudhui yanaweza kuficha habari. Ili kuchimbua data hii, tembelea [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).



***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia kiotomatiki** mchakato wa kazi uliojengwa na zana za jamii za **kisasa zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

## **Kuchimbua Data kutoka kwa Picha**

### **Kutambua Maelezo ya Picha na GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) hutumika kutambua aina za faili za picha na kutambua uharibifu unaowezekana. Tekeleza amri ifuatayo kuangalia picha:
```bash
./magick identify -verbose stego.jpg
```
Kujaribu kurekebisha picha iliyo haribika, kuongeza maoni ya metadata kunaweza kusaidia:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide kwa Kuficha Data**

Steghide inarahisisha kuficha data ndani ya faili za `JPEG, BMP, WAV, na AU`, inayoweza kuingiza na kutoa data iliyofichwa kwa kutumia encryption. Usanidi ni rahisi kwa kutumia `apt`, na [msimbo wa chanzo unapatikana kwenye GitHub](https://github.com/StefanoDeVuono/steghide).

**Amri:**
- `steghide info file` inaonyesha kama faili ina data iliyofichwa.
- `steghide extract -sf file [--passphrase password]` inatoa data iliyofichwa, nenosiri ni hiari.

Kwa uchimbaji wa wavuti, tembelea [tovuti hii](https://futureboy.us/stegano/decinput.html).

**Shambulio la Kuvunja Nenosiri kwa Kutumia Stegcracker:**
- Kujaribu kuvunja nenosiri kwenye Steghide, tumia [stegcracker](https://github.com/Paradoxis/StegCracker.git) kama ifuatavyo:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg kwa Faili za PNG na BMP**

zsteg inajihusisha na kufunua data iliyofichwa katika faili za PNG na BMP. Usanidi unafanywa kupitia `gem install zsteg`, na [chanzo chake kiko kwenye GitHub](https://github.com/zed-0xff/zsteg).

**Amri:**
- `zsteg -a faili` inatumia njia zote za ugunduzi kwenye faili.
- `zsteg -E faili` inabainisha mzigo wa uchimbaji wa data.

### **StegoVeritas na Stegsolve**

**stegoVeritas** huchunguza metadata, hufanya mabadiliko ya picha, na hutumia nguvu ya LSB miongoni mwa huduma zingine. Tumia `stegoveritas.py -h` kwa orodha kamili ya chaguo na `stegoveritas.py stego.jpg` kutekeleza uchunguzi wote.

**Stegsolve** inatumia vichujio vya rangi mbalimbali ili kufunua maandishi au ujumbe uliofichwa ndani ya picha. Inapatikana kwenye [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT kwa Ugunduzi wa Yaliyofichwa**

Teknolojia ya Fast Fourier Transform (FFT) inaweza kufunua yaliyofichwa ndani ya picha. Vyanzo muhimu ni pamoja na:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic kwenye GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy kwa Faili za Sauti na Picha**

Stegpy inaruhusu kuingiza habari kwenye faili za picha na sauti, ikisaidia muundo kama vile PNG, BMP, GIF, WebP, na WAV. Inapatikana kwenye [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck kwa Uchambuzi wa Faili za PNG**

Ili kuchambua faili za PNG au kuthibitisha uhalali wao, tumia:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Zana za ziada kwa Uchambuzi wa Picha**

Kwa uchunguzi zaidi, fikiria kutembelea:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Uchambuzi wa Kiwango cha Hitilafu ya Picha](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **Kuchota Data kutoka kwenye Nyimbo**

**Steganografia ya sauti** inatoa njia ya kipekee ya kuficha habari ndani ya faili za sauti. Zana tofauti hutumiwa kwa kuingiza au kupata maudhui yaliyofichwa.

### **Steghide (JPEG, BMP, WAV, AU)**
Steghide ni zana yenye uwezo wa kuficha data katika faili za JPEG, BMP, WAV, na AU. Maelekezo ya kina yanapatikana katika [hati ya mbinu za stego](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**
Zana hii inaweza kutumika na muundo mbalimbali ikiwa ni pamoja na PNG, BMP, GIF, WebP, na WAV. Kwa maelezo zaidi, tazama [sehemu ya Stegpy](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**
ffmpeg ni muhimu kwa ajili ya kutathmini uadilifu wa faili za sauti, kutoa taarifa za kina na kugundua tofauti yoyote.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**
WavSteg inafanya vizuri katika kuficha na kutoa data ndani ya faili za WAV kwa kutumia mkakati wa biti ndogo zaidi. Inapatikana kwenye [GitHub](https://github.com/ragibson/Steganography#WavSteg). Amri zinajumuisha:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**
Deepsound inaruhusu kusimbwa na kugundua habari ndani ya faili za sauti kwa kutumia AES-256. Inaweza kupakuliwa kutoka [ukurasa rasmi](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**
Zana muhimu kwa ukaguzi wa kina na uchambuzi wa faili za sauti, Sonic Visualizer inaweza kufunua vipengele vilivyofichwa ambavyo havigunduliki kwa njia nyingine. Tembelea [tovuti rasmi](https://www.sonicvisualiser.org/) kwa maelezo zaidi.

### **DTMF Tones - Dial Tones**
Kugundua sauti za DTMF katika faili za sauti kunaweza kufanikishwa kupitia zana za mtandaoni kama [hii ya kugundua DTMF](https://unframework.github.io/dtmf-detect/) na [DialABC](http://dialabc.com/sound/detect/index.html).

## **Mbinu Nyingine**

### **Binary Length SQRT - QR Code**
Data ya binary ambayo ina mraba wa nambari nzima inaweza kuwakilisha QR code. Tumia sehemu hii kuangalia:
```python
import math
math.sqrt(2500) #50
```
Kwa ubadilishaji wa binary kwenda picha, angalia [dcode](https://www.dcode.fr/binary-image). Kwa kusoma nambari za QR, tumia [msomaji wa nambari za mtandaoni hapa](https://online-barcode-reader.inliteresearch.com/).

### **Tafsiri ya Braille**
Kwa tafsiri ya Braille, [Branah Braille Translator](https://www.branah.com/braille-translator) ni rasilimali nzuri.

## **Marejeo**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Tafuta udhaifu unaofaa zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho wa kujitokeza, inapata matatizo katika mfumo wako wa teknolojia mzima, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
