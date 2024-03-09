# Partizioni/Sistemi di File/Carving

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Partizioni

Un hard disk o un **disco SSD possono contenere diverse partizioni** con lo scopo di separare fisicamente i dati.\
L'**unità minima** di un disco è il **settore** (normalmente composto da 512B). Quindi, la dimensione di ciascuna partizione deve essere un multiplo di quella dimensione.

### MBR (Master Boot Record)

È allocato nel **primo settore del disco dopo i 446B del codice di avvio**. Questo settore è essenziale per indicare al PC cosa e da dove una partizione dovrebbe essere montata.\
Consente fino a **4 partizioni** (al massimo **solo 1** può essere attiva/**avviabile**). Tuttavia, se hai bisogno di più partizioni puoi utilizzare **partizioni estese**. L'**ultimo byte** di questo primo settore è la firma del record di avvio **0x55AA**. Solo una partizione può essere contrassegnata come attiva.\
MBR consente **max 2,2TB**.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

Dai **byte 440 ai 443** dell'MBR puoi trovare la **Firma del Disco di Windows** (se viene utilizzato Windows). La lettera del drive logico del disco rigido dipende dalla Firma del Disco di Windows. Cambiare questa firma potrebbe impedire a Windows di avviarsi (strumento: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

**Formato**

| Offset      | Lunghezza  | Elemento            |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Codice di avvio      |
| 446 (0x1BE) | 16 (0x10)  | Prima Partizione     |
| 462 (0x1CE) | 16 (0x10)  | Seconda Partizione    |
| 478 (0x1DE) | 16 (0x10)  | Terza Partizione     |
| 494 (0x1EE) | 16 (0x10)  | Quarta Partizione    |
| 510 (0x1FE) | 2 (0x2)    | Firma 0x55 0xAA |

**Formato del Record di Partizione**

| Offset    | Lunghezza   | Elemento                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Flag attivo (0x80 = avviabile)                          |
| 1 (0x01)  | 1 (0x01) | Testa di inizio                                             |
| 2 (0x02)  | 1 (0x01) | Settore di inizio (bit 0-5); bit superiori del cilindro (6- 7) |
| 3 (0x03)  | 1 (0x01) | Bit più bassi del cilindro di inizio                           |
| 4 (0x04)  | 1 (0x01) | Codice tipo partizione (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01) | Testa di fine                                               |
| 6 (0x06)  | 1 (0x01) | Settore di fine (bit 0-5); bit superiori del cilindro (6- 7)   |
| 7 (0x07)  | 1 (0x01) | Bit più bassi del cilindro di fine                             |
| 8 (0x08)  | 4 (0x04) | Settori precedenti alla partizione (little endian)            |
| 12 (0x0C) | 4 (0x04) | Settori nella partizione                                   |

Per montare un MBR in Linux è necessario prima ottenere l'offset di inizio (puoi usare `fdisk` e il comando `p`)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

E poi utilizzare il seguente codice
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) è uno schema comune utilizzato per **specificare la posizione dei blocchi** di dati memorizzati su dispositivi di archiviazione informatica, generalmente sistemi di archiviazione secondari come i dischi rigidi. LBA è uno schema di indirizzamento lineare particolarmente semplice; **i blocchi sono localizzati da un indice intero**, con il primo blocco che corrisponde a LBA 0, il secondo a LBA 1, e così via.

### GPT (Tabella delle partizioni GUID)

La GUID Partition Table, nota come GPT, è preferita per le sue capacità avanzate rispetto a MBR (Master Boot Record). Distintiva per il suo **identificatore univoco globale** per le partizioni, la GPT si distingue in diversi modi:

* **Posizione e Dimensione**: Sia GPT che MBR iniziano a **settore 0**. Tuttavia, GPT opera su **64 bit**, a differenza dei 32 bit di MBR.
* **Limiti delle Partizioni**: GPT supporta fino a **128 partizioni** sui sistemi Windows e può ospitare fino a **9,4 ZB** di dati.
* **Nomi delle Partizioni**: Offre la possibilità di nominare le partizioni con fino a 36 caratteri Unicode.

**Resilienza e Recupero dei Dati**:

* **Ridondanza**: A differenza di MBR, GPT non limita la partizione e i dati di avvio a un unico luogo. Replica questi dati su tutto il disco, migliorando l'integrità e la resilienza dei dati.
* **Controllo di Ridondanza Ciclico (CRC)**: GPT utilizza il CRC per garantire l'integrità dei dati. Monitora attivamente la corruzione dei dati e, quando rilevata, GPT tenta di recuperare i dati corrotti da un'altra posizione del disco.

**MBR Protettivo (LBA0)**:

* GPT mantiene la compatibilità all'indietro attraverso un MBR protettivo. Questa funzionalità risiede nello spazio MBR legacy ma è progettata per impedire a vecchie utility basate su MBR di sovrascrivere erroneamente i dischi GPT, garantendo così l'integrità dei dati sui dischi formattati in GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID\_Partition\_Table\_Scheme.svg/800px-GUID\_Partition\_Table\_Scheme.svg.png](<../../../.gitbook/assets/image (491).png>)

**MBR Ibrido (LBA 0 + GPT)**

[Da Wikipedia](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

Nei sistemi operativi che supportano l'avvio basato su **GPT tramite servizi BIOS** anziché EFI, il primo settore può essere utilizzato anche per memorizzare la prima fase del codice del **bootloader**, ma **modificato** per riconoscere le **partizioni GPT**. Il bootloader nell'MBR non deve assumere una dimensione del settore di 512 byte.

**Intestazione della tabella delle partizioni (LBA 1)**

[Da Wikipedia](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

L'intestazione della tabella delle partizioni definisce i blocchi utilizzabili sul disco. Definisce anche il numero e la dimensione delle voci di partizione che compongono la tabella delle partizioni (offset 80 e 84 nella tabella).

| Offset    | Lunghezza | Contenuti                                                                                                                                                                        |
| --------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 byte   | Firma ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h o 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)su macchine little-endian) |
| 8 (0x08)  | 4 byte   | Revisione 1.0 (00h 00h 01h 00h) per UEFI 2.8                                                                                                                                     |
| 12 (0x0C) | 4 byte   | Dimensione intestazione in little endian (in byte, di solito 5Ch 00h 00h 00h o 92 byte)                                                                                          |
| 16 (0x10) | 4 byte   | [CRC32](https://en.wikipedia.org/wiki/CRC32) dell'intestazione (offset +0 fino alla dimensione dell'intestazione) in little endian, con questo campo azzerato durante il calcolo |
| 20 (0x14) | 4 byte   | Riservato; deve essere zero                                                                                                                                                      |
| 24 (0x18) | 8 byte   | LBA corrente (posizione di questa copia dell'intestazione)                                                                                                                       |
| 32 (0x20) | 8 byte   | LBA di backup (posizione dell'altra copia dell'intestazione)                                                                                                                     |
| 40 (0x28) | 8 byte   | Primo LBA utilizzabile per le partizioni (ultimo LBA della tabella delle partizioni primaria + 1)                                                                               |
| 48 (0x30) | 8 byte   | Ultimo LBA utilizzabile (primo LBA della tabella delle partizioni secondaria - 1)                                                                                                |
| 56 (0x38) | 16 byte  | GUID del disco in mixed endian                                                                                                                                                   |
| 72 (0x48) | 8 byte   | LBA iniziale di un array di voci di partizione (sempre 2 nella copia primaria)                                                                                                   |
| 80 (0x50) | 4 byte   | Numero di voci di partizione nell'array                                                                                                                                          |
| 84 (0x54) | 4 byte   | Dimensione di una singola voce di partizione (di solito 80h o 128)                                                                                                               |
| 88 (0x58) | 4 byte   | CRC32 dell'array di voci di partizione in little endian                                                                                                                          |
| 92 (0x5C) | \*        | Riservato; deve essere zero per il resto del blocco (420 byte per una dimensione del settore di 512 byte; ma può essere maggiore con dimensioni del settore più grandi)         |

**Voci di partizione (LBA 2–33)**

| Formato voce di partizione GUID |          |                                                                                                                   |
| ------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Offset                          | Lunghezza | Contenuti                                                                                                          |
| 0 (0x00)                        | 16 byte  | [GUID del tipo di partizione](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (mixed endian) |
| 16 (0x10)                       | 16 byte  | GUID di partizione univoco (mixed endian)                                                                          |
| 32 (0x20)                       | 8 byte   | Primo LBA ([little endian](https://en.wikipedia.org/wiki/Little\_endian))                                         |
| 40 (0x28)                       | 8 byte   | Ultimo LBA (inclusivo, di solito dispari)                                                                          |
| 48 (0x30)                       | 8 byte   | Flag attributi (ad es. il bit 60 indica sola lettura)                                                             |
| 56 (0x38)                       | 72 byte  | Nome della partizione (36 unità di codice UTF-16LE)                                                               |

**Tipi di Partizioni**

![](<../../../.gitbook/assets/image (492).png>)

Ulteriori tipi di partizioni in [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### Ispezione

Dopo aver montato l'immagine forense con [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), è possibile ispezionare il primo settore utilizzando lo strumento Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Nell'immagine seguente è stato rilevato un **MBR** nel **settore 0** e interpretato:

![](<../../../.gitbook/assets/image (494).png>)

Se fosse presente una **tabella GPT invece di un MBR**, dovrebbe apparire la firma _EFI PART_ nel **settore 1** (che nell'immagine precedente è vuoto).
## Sistemi di file

### Elenco dei file-system di Windows

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

Il file system **FAT (File Allocation Table)** è progettato attorno al suo componente principale, la tabella di allocazione dei file, posizionata all'inizio del volume. Questo sistema protegge i dati mantenendo **due copie** della tabella, garantendo l'integrità dei dati anche se una è danneggiata. La tabella, insieme alla cartella radice, deve trovarsi in una **posizione fissa**, cruciale per il processo di avvio del sistema.

L'unità di archiviazione di base del file system è un **cluster, di solito 512B**, composto da più settori. FAT si è evoluto attraverso le versioni:

* **FAT12**, supporta indirizzi di cluster a 12 bit e gestisce fino a 4078 cluster (4084 con UNIX).
* **FAT16**, migliorando con indirizzi a 16 bit, consentendo così di ospitare fino a 65.517 cluster.
* **FAT32**, avanzando ulteriormente con indirizzi a 32 bit, consentendo un impressionante numero di 268.435.456 cluster per volume.

Una limitazione significativa attraverso le versioni di FAT è la **dimensione massima del file di 4GB**, imposta dal campo a 32 bit utilizzato per l'archiviazione delle dimensioni dei file.

Componenti chiave della directory radice, in particolare per FAT12 e FAT16, includono:

* **Nome del file/cartella** (fino a 8 caratteri)
* **Attributi**
* **Date di creazione, modifica e ultimo accesso**
* **Indirizzo della tabella FAT** (indica il cluster di avvio del file)
* **Dimensione del file**

### EXT

**Ext2** è il file system più comune per le **partizioni senza journaling** (partizioni che non cambiano molto) come la partizione di avvio. **Ext3/4** sono **con journaling** e vengono utilizzati di solito per il **resto delle partizioni**.

## **Metadati**

Alcuni file contengono metadati. Queste informazioni riguardano il contenuto del file che a volte potrebbe essere interessante per un analista poiché, a seconda del tipo di file, potrebbe contenere informazioni come:

* Titolo
* Versione di MS Office utilizzata
* Autore
* Date di creazione e ultima modifica
* Modello della fotocamera
* Coordinate GPS
* Informazioni sull'immagine

Puoi utilizzare strumenti come [**exiftool**](https://exiftool.org) e [**Metadiver**](https://www.easymetadata.com/metadiver-2/) per ottenere i metadati di un file.

## **Recupero dei file eliminati**

### File eliminati registrati

Come visto in precedenza, ci sono diversi luoghi in cui il file viene ancora salvato dopo essere stato "eliminato". Questo perché di solito l'eliminazione di un file da un file system lo contrassegna come eliminato ma i dati non vengono toccati. Quindi, è possibile ispezionare i registri dei file (come il MFT) e trovare i file eliminati.

Inoltre, il sistema operativo di solito salva molte informazioni sulle modifiche al file system e sui backup, quindi è possibile provare a utilizzarle per recuperare il file o il maggior numero possibile di informazioni.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **Intaglio dei file**

**L'intaglio dei file** è una tecnica che cerca di **trovare file nel mucchio di dati**. Ci sono 3 modi principali con cui funzionano gli strumenti come questo: **Basato su intestazioni e piedi di pagina dei tipi di file**, basato su **strutture dei tipi di file** e basato sul **contenuto** stesso.

Nota che questa tecnica **non funziona per recuperare file frammentati**. Se un file **non è memorizzato in settori contigui**, allora questa tecnica non sarà in grado di trovarlo o almeno parte di esso.

Ci sono diversi strumenti che puoi utilizzare per l'intaglio dei file indicando i tipi di file che desideri cercare

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Intaglio dei **Dati**

L'intaglio dei dati è simile all'intaglio dei file ma **invece di cercare file completi, cerca frammenti interessanti** di informazioni.\
Ad esempio, anziché cercare un file completo contenente URL registrati, questa tecnica cercherà gli URL.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Eliminazione sicura

Ovviamente, ci sono modi per **eliminare "in modo sicuro" file e parte dei log su di essi**. Ad esempio, è possibile **sovrascrivere il contenuto** di un file con dati spazzatura più volte, e quindi **rimuovere** i **log** dal **$MFT** e **$LOGFILE** riguardo al file, e **rimuovere le copie shadow del volume**.\
Potresti notare che anche eseguendo quell'azione potrebbero esserci **altre parti in cui l'esistenza del file è ancora registrata**, ed è vero e parte del lavoro di un professionista forense è trovarle.

## Riferimenti

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusivi [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
