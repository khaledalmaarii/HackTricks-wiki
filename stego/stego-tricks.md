# Trikovi Steganografije

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini da podržite HackTricks:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje trikove hakovanja slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretrage pretnji, pronalazi probleme u celokupnom tehnološkom sklopu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte ga besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Izdvajanje podataka iz fajlova**

### **Binwalk**
Alat za pretragu binarnih fajlova u potrazi za skrivenim fajlovima i podacima. Instalira se putem `apt`-a, a izvorni kod je dostupan na [GitHub-u](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**
Vraća datoteke na osnovu njihovih zaglavlja i podnožja, korisno za png slike. Instalira se putem `apt` sa izvorom na [GitHub-u](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**
Pomaže pri pregledu metapodataka datoteke, dostupan [ovde](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**
Slično kao exiftool, za pregledanje metapodataka. Može se instalirati putem `apt`, izvor na [GitHub-u](https://github.com/Exiv2/exiv2), i ima [zvaničnu veb stranicu](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Fajl**
Identifikujte vrstu fajla sa kojim se bavite.

### **Niske**
Izdvaja čitljive niske iz fajlova, koristeći različite postavke enkodiranja za filtriranje rezultata.
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
### **Poređenje (cmp)**
Korisno za poređenje izmenjenog fajla sa njegovom originalnom verzijom pronađenom online.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Izdvajanje skrivenih podataka u tekstu**

### **Skriveni podaci u razmacima**
Nevidljivi znakovi u naizgled praznim razmacima mogu sakriti informacije. Da biste izvukli ove podatke, posetite [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).



***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** koji se pokreću najnaprednijim alatima zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

## **Izdvajanje podataka iz slika**

### **Identifikacija detalja slike pomoću GraphicMagick-a**

[GraphicMagick](https://imagemagick.org/script/download.php) služi za određivanje vrsta datoteka slika i identifikaciju potencijalnih oštećenja. Izvršite sledeću komandu da biste pregledali sliku:
```bash
./magick identify -verbose stego.jpg
```
Da biste pokušali popraviti oštećenu sliku, dodavanje komentara u metapodatke može pomoći:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide za sakrivanje podataka**

Steghide omogućava sakrivanje podataka unutar `JPEG, BMP, WAV i AU` fajlova, sposoban je za ugradnju i izvlačenje šifrovanih podataka. Instalacija je jednostavna korišćenjem `apt`-a, a [izvorni kod je dostupan na GitHub-u](https://github.com/StefanoDeVuono/steghide).

**Komande:**
- `steghide info file` otkriva da li fajl sadrži sakrivene podatke.
- `steghide extract -sf file [--passphrase password]` izvlači sakrivene podatke, lozinka je opciona.

Za izvlačenje putem veba, posetite [ovu veb stranicu](https://futureboy.us/stegano/decinput.html).

**Bruteforce napad sa Stegcracker-om:**
- Da biste pokušali dešifrovanje lozinke za Steghide, koristite [stegcracker](https://github.com/Paradoxis/StegCracker.git) na sledeći način:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg za PNG i BMP fajlove**

zsteg se specijalizuje za otkrivanje skrivenih podataka u PNG i BMP fajlovima. Instalacija se vrši putem `gem install zsteg`, a izvor možete pronaći na [GitHub-u](https://github.com/zed-0xff/zsteg).

**Komande:**
- `zsteg -a fajl` primenjuje sve metode detekcije na fajl.
- `zsteg -E fajl` specificira payload za ekstrakciju podataka.

### **StegoVeritas i Stegsolve**

**stegoVeritas** proverava metapodatke, vrši transformacije slike i primenjuje LSB brute force metodu, između ostalih funkcionalnosti. Koristite `stegoveritas.py -h` za punu listu opcija i `stegoveritas.py stego.jpg` za izvršavanje svih provera.

**Stegsolve** primenjuje različite filtere boja kako bi otkrio skrivene tekstove ili poruke unutar slika. Dostupan je na [GitHub-u](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT za otkrivanje skrivenog sadržaja**

Tehnike brze Furijeove transformacije (FFT) mogu otkriti skriveni sadržaj u slikama. Korisni resursi uključuju:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic na GitHub-u](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy za audio i slikovne fajlove**

Stegpy omogućava ugradnju informacija u slikovne i audio fajlove, podržavajući formate kao što su PNG, BMP, GIF, WebP i WAV. Dostupan je na [GitHub-u](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck za analizu PNG fajlova**

Za analizu PNG fajlova ili proveru njihove autentičnosti, koristite:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Dodatni alati za analizu slika**

Za dalje istraživanje, razmotrite posetu:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Analiza nivoa greške slike](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **Izdvajanje podataka iz audio zapisa**

**Audio steganografija** nudi jedinstveni metod za prikrivanje informacija unutar zvučnih fajlova. Različiti alati se koriste za ugradnju ili izvlačenje skrivenog sadržaja.

### **Steghide (JPEG, BMP, WAV, AU)**
Steghide je vešti alat dizajniran za skrivanje podataka u JPEG, BMP, WAV i AU fajlovima. Detaljne instrukcije su dostupne u [dokumentaciji o trikovima steganografije](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**
Ovaj alat je kompatibilan sa različitim formatima, uključujući PNG, BMP, GIF, WebP i WAV. Za više informacija, pogledajte [odeljak o Stegpy-u](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**
ffmpeg je ključan za procenu integriteta audio fajlova, ističući detaljne informacije i otkrivanje eventualnih neslaganja.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**
WavSteg se ističe u skrivanju i izvlačenju podataka unutar WAV fajlova koristeći strategiju najmanje značajnog bita. Dostupan je na [GitHub-u](https://github.com/ragibson/Steganography#WavSteg). Komande uključuju:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**
Deepsound omogućava šifrovanje i otkrivanje informacija unutar zvučnih fajlova koristeći AES-256. Može se preuzeti sa [zvanične stranice](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**
Neprocenjiv alat za vizuelnu i analitičku inspekciju audio fajlova, Sonic Visualizer može otkriti skrivene elemente koji nisu detektovani na druge načine. Posetite [zvaničnu veb stranicu](https://www.sonicvisualiser.org/) za više informacija.

### **DTMF Tones - Dial Tones**
Detekcija DTMF tonova u audio fajlovima može se postići putem online alata kao što su [ovaj DTMF detektor](https://unframework.github.io/dtmf-detect/) i [DialABC](http://dialabc.com/sound/detect/index.html).

## **Druge tehnike**

### **Binary Length SQRT - QR Code**
Binarni podaci koji se kvadriraju u ceo broj mogu predstavljati QR kod. Koristite ovaj kod da proverite:
```python
import math
math.sqrt(2500) #50
```
Za konverziju binarnog u sliku, proverite [dcode](https://www.dcode.fr/binary-image). Za čitanje QR kodova, koristite [ovaj online čitač barkoda](https://online-barcode-reader.inliteresearch.com/).

### **Prevod na Braillovu azbuku**
Za prevod na Braillovu azbuku, odličan resurs je [Branah Braille Translator](https://www.branah.com/braille-translator).

## **Reference**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretnje, pronalazi probleme u celom vašem tehnološkom skupu, od API-ja do veb aplikacija i sistemima u oblaku. [**Isprobajte ga besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
