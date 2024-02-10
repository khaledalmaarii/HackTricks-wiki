# Κόλπα Stego

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που είναι πιο σημαντικές, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Το Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, βρίσκει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίβα, από τα APIs μέχρι τις web εφαρμογές και τα συστήματα cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Εξαγωγή Δεδομένων από Αρχεία**

### **Binwalk**
Ένα εργαλείο για την αναζήτηση δυαδικών αρχείων για ενσωματωμένα κρυφά αρχεία και δεδομένα. Εγκαθίσταται μέσω `apt` και ο πηγαίος κώδικας του είναι διαθέσιμος στο [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**
Ανακτά αρχεία με βάση τους κεφαλίδες και τα υποσέλιδα τους, χρήσιμο για εικόνες png. Εγκαθίσταται μέσω `apt` με την πηγή του στο [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**
Βοηθά στην προβολή μεταδεδομένων αρχείων, διαθέσιμο [εδώ](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**
Παρόμοιο με το exiftool, για την προβολή μεταδεδομένων. Εγκαταστάσιμο μέσω `apt`, πηγαίος κώδικας στο [GitHub](https://github.com/Exiv2/exiv2), και έχει μια [επίσημη ιστοσελίδα](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Αρχείο**
Αναγνωρίστε τον τύπο του αρχείου με το οποίο ασχολείστε.

### **Συμβολοσειρές**
Εξάγει αναγνώσιμες συμβολοσειρές από αρχεία, χρησιμοποιώντας διάφορες ρυθμίσεις κωδικοποίησης για να φιλτράρει την έξοδο.
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
### **Σύγκριση (cmp)**
Χρήσιμο για τη σύγκριση ενός τροποποιημένου αρχείου με την αρχική του έκδοση που βρέθηκε online.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Εξαγωγή Κρυμμένων Δεδομένων από Κείμενο**

### **Κρυμμένα Δεδομένα σε Διαστήματα**
Αόρατοι χαρακτήρες σε φαινομενικά κενά διαστήματα μπορεί να κρύβουν πληροφορίες. Για να εξαγάγετε αυτά τα δεδομένα, επισκεφθείτε [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).



***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να αυτοματοποιήσετε ροές εργασίας με τα πιο προηγμένα εργαλεία της παγκόσμιας κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

## **Εξαγωγή Δεδομένων από Εικόνες**

### **Αναγνώριση Λεπτομερειών Εικόνας με το GraphicMagick**

Το [GraphicMagick](https://imagemagick.org/script/download.php) χρησιμοποιείται για να προσδιορίσει τους τύπους αρχείων εικόνας και να ανιχνεύσει πιθανή καταστροφή. Εκτελέστε την παρακάτω εντολή για να επιθεωρήσετε μια εικόνα:
```bash
./magick identify -verbose stego.jpg
```
Για να προσπαθήσετε να επιδιορθώσετε μια κατεστραμμένη εικόνα, μπορεί να βοηθήσει η προσθήκη ενός σχολίου μεταδεδομένων:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide για Απόκρυψη Δεδομένων**

Το Steghide διευκολύνει την απόκρυψη δεδομένων μέσα σε αρχεία `JPEG, BMP, WAV και AU`, ικανό να ενσωματώνει και να εξάγει κρυπτογραφημένα δεδομένα. Η εγκατάσταση είναι απλή χρησιμοποιώντας το `apt`, και ο [πηγαίος κώδικας είναι διαθέσιμος στο GitHub](https://github.com/StefanoDeVuono/steghide).

**Εντολές:**
- Η εντολή `steghide info file` αποκαλύπτει εάν ένα αρχείο περιέχει κρυμμένα δεδομένα.
- Η εντολή `steghide extract -sf file [--passphrase password]` εξάγει τα κρυμμένα δεδομένα, με προαιρετικό κωδικό πρόσβασης.

Για εξαγωγή μέσω ιστοσελίδας, επισκεφθείτε [αυτήν την ιστοσελίδα](https://futureboy.us/stegano/decinput.html).

**Επίθεση με Βίαιη Δοκιμή (Bruteforce) χρησιμοποιώντας το Stegcracker:**
- Για να δοκιμάσετε την αποκρυπτογράφηση κωδικού πρόσβασης στο Steghide, χρησιμοποιήστε το [stegcracker](https://github.com/Paradoxis/StegCracker.git) ως εξής:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg για αρχεία PNG και BMP**

Το zsteg εξειδικεύεται στον εντοπισμό κρυμμένων δεδομένων σε αρχεία PNG και BMP. Η εγκατάσταση γίνεται μέσω `gem install zsteg`, με την [πηγή του στο GitHub](https://github.com/zed-0xff/zsteg).

**Εντολές:**
- Η εντολή `zsteg -a file` εφαρμόζει όλες τις μεθόδους ανίχνευσης σε ένα αρχείο.
- Η εντολή `zsteg -E file` καθορίζει ένα φορτίο για την εξαγωγή δεδομένων.

### **StegoVeritas και Stegsolve**

Το **stegoVeritas** ελέγχει τα μεταδεδομένα, εκτελεί μετασχηματισμούς εικόνας και εφαρμόζει αναζήτηση με βία LSB μεταξύ άλλων χαρακτηριστικών. Χρησιμοποιήστε `stegoveritas.py -h` για μια πλήρη λίστα επιλογών και `stegoveritas.py stego.jpg` για να εκτελέσετε όλους τους ελέγχους.

Το **Stegsolve** εφαρμόζει διάφορα φίλτρα χρωμάτων για να αποκαλύψει κρυμμένα κείμενα ή μηνύματα μέσα σε εικόνες. Είναι διαθέσιμο στο [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT για την Ανίχνευση Κρυμμένου Περιεχομένου**

Οι τεχνικές γρήγορης μετασχηματισμού Fourier (FFT) μπορούν να αποκαλύψουν κρυμμένο περιεχόμενο σε εικόνες. Χρήσιμοι πόροι περιλαμβάνουν:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic στο GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy για Αρχεία Ήχου και Εικόνας**

Το Stegpy επιτρέπει την ενσωμάτωση πληροφοριών σε αρχεία εικόνας και ήχου, υποστηρίζοντας μορφές όπως PNG, BMP, GIF, WebP και WAV. Είναι διαθέσιμο στο [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck για Ανάλυση Αρχείων PNG**

Για να αναλύσετε αρχεία PNG ή να επαληθεύσετε την αυθεντικότητά τους, χρησιμοποιήστε:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Επιπλέον Εργαλεία για Ανάλυση Εικόνων**

Για περαιτέρω εξερεύνηση, σκεφτείτε να επισκεφθείτε:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **Εξαγωγή Δεδομένων από Ήχους**

Η **ακουστική στεγανογραφία** προσφέρει ένα μοναδικό τρόπο για να κρύψετε πληροφορίες μέσα σε αρχεία ήχου. Διάφορα εργαλεία χρησιμοποιούνται για την ενσωμάτωση ή την ανάκτηση κρυμμένου περιεχομένου.

### **Steghide (JPEG, BMP, WAV, AU)**
Το Steghide είναι ένα ευέλικτο εργαλείο σχεδιασμένο για την απόκρυψη δεδομένων σε αρχεία JPEG, BMP, WAV και AU. Λεπτομερείς οδηγίες παρέχονται στην [τεκμηρίωση τεχνικών stego](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**
Αυτό το εργαλείο είναι συμβατό με μια ποικιλία μορφών, συμπεριλαμβανομένων των PNG, BMP, GIF, WebP και WAV. Για περισσότερες πληροφορίες, ανατρέξτε στην [ενότητα Stegpy](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**
Το ffmpeg είναι ζωτικής σημασίας για την αξιολόγηση της ακεραιότητας αρχείων ήχου, την αναδειξη λεπτομερειών και τον εντοπισμό οποιωνδήποτε ανωμαλιών.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**
Το WavSteg ξεχωρίζει στην απόκρυψη και εξαγωγή δεδομένων μέσα σε αρχεία WAV χρησιμοποιώντας τη στρατηγική του λιγότερο σημαντικού ψηφίου. Είναι προσβάσιμο στο [GitHub](https://github.com/ragibson/Steganography#WavSteg). Οι εντολές περιλαμβάνουν:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**
Το Deepsound επιτρέπει την κρυπτογράφηση και ανίχνευση πληροφοριών μέσα σε αρχεία ήχου χρησιμοποιώντας το AES-256. Μπορεί να γίνει λήψη από [την επίσημη σελίδα](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**
Ένα ανεκτίμητο εργαλείο για οπτική και αναλυτική επιθεώρηση αρχείων ήχου, το Sonic Visualizer μπορεί να αποκαλύψει κρυμμένα στοιχεία που δεν είναι ανιχνεύσιμα με άλλα μέσα. Επισκεφθείτε την [επίσημη ιστοσελίδα](https://www.sonicvisualiser.org/) για περισσότερες πληροφορίες.

### **DTMF Tones - Ήχοι Κλήσης**
Η ανίχνευση των ήχων DTMF σε αρχεία ήχου μπορεί να επιτευχθεί μέσω online εργαλείων όπως αυτός ο ανιχνευτής DTMF](https://unframework.github.io/dtmf-detect/) και το [DialABC](http://dialabc.com/sound/detect/index.html).

## **Άλλες Τεχνικές**

### **Binary Length SQRT - QR Code**
Δυαδικά δεδομένα που αποτελούν τετράγωνο ενός ακέραιου αριθμού μπορεί να αντιπροσωπεύουν έναν κωδικό QR. Χρησιμοποιήστε αυτό το απόσπασμα για να το ελέγξετε:
```python
import math
math.sqrt(2500) #50
```
Για τη μετατροπή από δυαδικό σε εικόνα, ελέγξτε το [dcode](https://www.dcode.fr/binary-image). Για την ανάγνωση QR κωδικών, χρησιμοποιήστε [αυτόν τον online αναγνώστη barcode](https://online-barcode-reader.inliteresearch.com/).

### **Μετάφραση Braille**
Για τη μετάφραση Braille, το [Branah Braille Translator](https://www.branah.com/braille-translator) είναι ένα εξαιρετικό εργαλείο.

## **Αναφορές**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που έχουν μεγαλύτερη σημασία, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Το Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίχημα, από APIs έως web εφαρμογές και συστήματα cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
