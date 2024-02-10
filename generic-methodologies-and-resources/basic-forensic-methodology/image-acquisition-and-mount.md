# Acquisizione dell'immagine e montaggio

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Acquisizione

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
dcfldd è un'utility di acquisizione di immagini forensi che può essere utilizzata per creare copie bit a bit di un'immagine di un dispositivo di archiviazione. È un'alternativa più avanzata al comando dd e offre funzionalità aggiuntive come il calcolo dell'hash MD5 e la registrazione delle informazioni di acquisizione.
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTK Imager

Puoi [**scaricare FTK Imager da qui**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1).
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

Puoi generare un'immagine del disco utilizzando gli [**strumenti ewf**](https://github.com/libyal/libewf).
```bash
ewfacquire /dev/sdb
#Name: evidence
#Case number: 1
#Description: A description for the case
#Evidence number: 1
#Examiner Name: Your name
#Media type: fixed
#Media characteristics: physical
#File format: encase6
#Compression method: deflate
#Compression level: fast

#Then use default values
#It will generate the disk image in the current directory
```
## Mounta

### Diversi tipi

In **Windows** puoi provare ad utilizzare la versione gratuita di Arsenal Image Mounter ([https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)) per **montare l'immagine forense**.

### Raw
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF

L'acquisizione di immagini è un passaggio fondamentale nella metodologia forense. Una delle tecniche utilizzate per acquisire immagini di dispositivi di archiviazione è l'utilizzo di file immagine EWF (Expert Witness Format). Questo formato è ampiamente supportato da molti strumenti forensi e consente di acquisire un'immagine bit a bit di un dispositivo di archiviazione, inclusi tutti i dati, i file eliminati e lo spazio non allocato.

Per acquisire un'immagine utilizzando il formato EWF, è necessario utilizzare uno strumento come `ewfacquire`. Questo strumento consente di specificare il dispositivo di archiviazione di destinazione e il percorso del file immagine EWF da creare. Durante il processo di acquisizione, `ewfacquire` crea un file immagine EWF che rappresenta esattamente il contenuto del dispositivo di archiviazione.

Una volta acquisita l'immagine EWF, è possibile montarla come dispositivo di archiviazione virtuale utilizzando lo strumento `ewfmount`. Questo consente di accedere ai dati contenuti nell'immagine come se fossero presenti su un dispositivo di archiviazione fisico. È possibile esaminare i file, recuperare dati eliminati e analizzare lo spazio non allocato per individuare potenziali prove.

L'utilizzo di file immagine EWF per l'acquisizione e il montaggio delle immagini offre numerosi vantaggi nella metodologia forense, tra cui la preservazione dell'integrità dei dati, la possibilità di lavorare con immagini di grandi dimensioni e la compatibilità con molti strumenti forensi.
```bash
#Get file type
file evidence.E01
evidence.E01: EWF/Expert Witness/EnCase image file format

#Transform to raw
mkdir output
ewfmount evidence.E01 output/
file output/ewf1
output/ewf1: Linux rev 1.0 ext4 filesystem data, UUID=05acca66-d042-4ab2-9e9c-be813be09b24 (needs journal recovery) (extents) (64bit) (large files) (huge files)

#Mount
mount output/ewf1 -o ro,norecovery /mnt
```
### ArsenalImageMounter

È un'applicazione Windows per montare volumi. Puoi scaricarla qui [https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)

### Errori

* **`impossibile montare /dev/loop0 in sola lettura`** in questo caso è necessario utilizzare i flag **`-o ro,norecovery`**
* **`tipo di file system errato, opzione errata, superblock errato su /dev/loop0, mancante codepage o programma di assistenza, o altro errore.`** in questo caso il montaggio è fallito poiché l'offset del file system è diverso da quello dell'immagine del disco. È necessario trovare la dimensione del settore e il settore di avvio:
```bash
fdisk -l disk.img
Disk disk.img: 102 MiB, 106954648 bytes, 208896 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00495395

Device        Boot Start    End Sectors  Size Id Type
disk.img1       2048 208895  206848  101M  1 FAT12
```
Nota che la dimensione del settore è **512** e l'inizio è **2048**. Successivamente monta l'immagine in questo modo:
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
