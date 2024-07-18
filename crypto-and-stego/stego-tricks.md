# Trucchi di Stego

{% hint style="success" %}
Impara e pratica l'Hacking su AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di GitHub.

</details>
{% endhint %}

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## **Estrarre Dati da File**

### **Binwalk**

Uno strumento per cercare file binari per file e dati nascosti incorporati. Viene installato tramite `apt` e la sua sorgente è disponibile su [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Principale**

Recupera file in base all'intestazione e al piè di pagina, utile per immagini png. Installato tramite `apt` con la sua sorgente su [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Aiuta a visualizzare i metadati dei file, disponibile [qui](https://www.sno.phy.queensu.ca/\~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Simile ad exiftool, per la visualizzazione dei metadati. Installabile tramite `apt`, sorgente su [GitHub](https://github.com/Exiv2/exiv2), e ha un [sito web ufficiale](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **File**

Identifica il tipo di file con cui stai lavorando.

### **Strings**

Estrae stringhe leggibili dai file, utilizzando diverse impostazioni di codifica per filtrare l'output.
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
### **Confronto (cmp)**

Utile per confrontare un file modificato con la sua versione originale trovata online.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Estrazione di Dati Nascosti nel Testo**

### **Dati Nascosti negli Spazi**

I caratteri invisibili in spazi apparentemente vuoti possono nascondere informazioni. Per estrarre questi dati, visita [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Estrazione di Dati dalle Immagini**

### **Identificare i Dettagli dell'Immagine con GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) serve per determinare i tipi di file immagine e identificare potenziali corruzioni. Esegui il comando seguente per ispezionare un'immagine:
```bash
./magick identify -verbose stego.jpg
```
Per tentare di riparare un'immagine danneggiata, potrebbe essere utile aggiungere un commento di metadati:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide per il Nascondimento dei Dati**

Steghide facilita il nascondimento dei dati all'interno dei file `JPEG, BMP, WAV e AU`, in grado di incorporare ed estrarre dati criptati. L'installazione è semplice utilizzando `apt`, e il [codice sorgente è disponibile su GitHub](https://github.com/StefanoDeVuono/steghide).

**Comandi:**

* `steghide info file` rivela se un file contiene dati nascosti.
* `steghide extract -sf file [--passphrase password]` estrae i dati nascosti, password opzionale.

Per l'estrazione basata sul web, visita [questo sito web](https://futureboy.us/stegano/decinput.html).

**Attacco di Forza Bruta con Stegcracker:**

* Per tentare il cracking della password su Steghide, utilizza [stegcracker](https://github.com/Paradoxis/StegCracker.git) nel seguente modo:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg per file PNG e BMP**

zsteg si specializza nel rivelare dati nascosti nei file PNG e BMP. L'installazione avviene tramite `gem install zsteg`, con la sua [fonte su GitHub](https://github.com/zed-0xff/zsteg).

**Comandi:**

* `zsteg -a file` applica tutti i metodi di rilevamento su un file.
* `zsteg -E file` specifica un payload per l'estrazione dei dati.

### **StegoVeritas e Stegsolve**

**stegoVeritas** controlla i metadati, esegue trasformazioni dell'immagine e applica la forza bruta LSB tra le altre funzionalità. Utilizza `stegoveritas.py -h` per un elenco completo delle opzioni e `stegoveritas.py stego.jpg` per eseguire tutti i controlli.

**Stegsolve** applica vari filtri di colore per rivelare testi o messaggi nascosti nelle immagini. È disponibile su [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT per il rilevamento di contenuti nascosti**

Le tecniche di Trasformata di Fourier Veloce (FFT) possono rivelare contenuti nascosti nelle immagini. Risorse utili includono:

* [Demo EPFL](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [FFTStegPic su GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy per file audio e immagine**

Stegpy consente di incorporare informazioni nei file audio e immagine, supportando formati come PNG, BMP, GIF, WebP e WAV. È disponibile su [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck per l'analisi dei file PNG**
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Strumenti aggiuntivi per l'analisi delle immagini**

Per ulteriori esplorazioni, considera di visitare:

* [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
* [Analisi del livello di errore dell'immagine](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
* [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
* [OpenStego](https://www.openstego.com/)
* [DIIT](https://diit.sourceforge.net/)

## **Estrarre dati dagli audio**

La **steganografia audio** offre un metodo unico per nascondere informazioni nei file audio. Diversi strumenti sono utilizzati per incorporare o recuperare contenuti nascosti.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide è uno strumento versatile progettato per nascondere dati nei file JPEG, BMP, WAV e AU. Istruzioni dettagliate sono fornite nella [documentazione dei trucchi di stego](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Questo strumento è compatibile con una varietà di formati tra cui PNG, BMP, GIF, WebP e WAV. Per ulteriori informazioni, consulta la [sezione di Stegpy](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg è cruciale per valutare l'integrità dei file audio, evidenziando informazioni dettagliate e individuando eventuali discrepanze.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg eccelle nel nascondere ed estrarre dati all'interno dei file WAV utilizzando la strategia del bit meno significativo. È accessibile su [GitHub](https://github.com/ragibson/Steganography#WavSteg). I comandi includono:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound consente la crittografia e il rilevamento di informazioni all'interno dei file audio utilizzando AES-256. Può essere scaricato dalla [pagina ufficiale](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Uno strumento prezioso per l'ispezione visiva e analitica dei file audio, Sonic Visualizer può rivelare elementi nascosti non rilevabili con altri mezzi. Visita il [sito ufficiale](https://www.sonicvisualiser.org/) per ulteriori informazioni.

### **Toni DTMF - Toni di Selezione**

Il rilevamento dei toni DTMF nei file audio può essere realizzato attraverso strumenti online come [questo rilevatore DTMF](https://unframework.github.io/dtmf-detect/) e [DialABC](http://dialabc.com/sound/detect/index.html).

## **Altre Tecniche**

### **Lunghezza Binaria SQRT - Codice QR**

I dati binari che danno un numero intero potrebbero rappresentare un codice QR. Utilizza questo snippet per controllare:
```python
import math
math.sqrt(2500) #50
```
### **Traduzione in Braille**

Per tradurre in Braille, il [Traduttore Braille di Branah](https://www.branah.com/braille-translator) è una risorsa eccellente.

## **Riferimenti**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

**Gruppo di Sicurezza Try Hard**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
