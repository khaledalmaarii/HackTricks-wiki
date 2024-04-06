# Firmware Analysis

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Introduzione**

Il firmware è un software essenziale che consente ai dispositivi di funzionare correttamente gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui gli utenti interagiscono. È memorizzato in memoria permanente, garantendo che il dispositivo possa accedere alle istruzioni vitali dal momento in cui viene acceso, portando al lancio del sistema operativo. Esaminare e potenzialmente modificare il firmware è un passaggio critico per identificare vulnerabilità di sicurezza.

## **Raccolta di informazioni**

La **raccolta di informazioni** è un passaggio iniziale fondamentale per comprendere la composizione di un dispositivo e le tecnologie che utilizza. Questo processo prevede la raccolta di dati su:

* L'architettura della CPU e il sistema operativo che esegue
* Specifiche del bootloader
* Layout hardware e datasheet
* Metriche del codice sorgente e posizioni delle origini
* Librerie esterne e tipi di licenza
* Storico degli aggiornamenti e certificazioni regolamentari
* Diagrammi architettonici e di flusso
* Valutazioni di sicurezza e vulnerabilità identificate

A tale scopo, gli strumenti di **open-source intelligence (OSINT)** sono preziosi, così come l'analisi di eventuali componenti software open-source disponibili attraverso processi di revisione manuali e automatizzati. Strumenti come [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) offrono analisi statica gratuita che può essere sfruttata per individuare potenziali problemi.

## **Acquisizione del Firmware**

L'ottenimento del firmware può essere affrontato attraverso vari mezzi, ognuno con il proprio livello di complessità:

* **Direttamente** dalla fonte (sviluppatori, produttori)
* **Costruendolo** seguendo le istruzioni fornite
* **Scaricandolo** dai siti di supporto ufficiali
* Utilizzando **query Google dork** per trovare file firmware ospitati
* Accedendo **direttamente allo storage cloud**, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
* Interferendo con **aggiornamenti** tramite tecniche man-in-the-middle
* **Estrazione** dal dispositivo tramite connessioni come **UART**, **JTAG** o **PICit**
* **Sniffing** delle richieste di aggiornamento all'interno della comunicazione del dispositivo
* Identificazione e utilizzo di **punti di aggiornamento codificati**
* **Dumping** dal bootloader o dalla rete
* **Rimozione e lettura** del chip di archiviazione, quando tutto il resto fallisce, utilizzando strumenti hardware appropriati

## Analisi del firmware

Ora che **hai il firmware**, devi estrarre informazioni su di esso per sapere come trattarlo. Puoi utilizzare diversi strumenti per questo:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Se non trovi molto con quegli strumenti, controlla l'**entropia** dell'immagine con `binwalk -E <bin>`. Se l'entropia è bassa, è improbabile che sia criptata. Se l'entropia è alta, è probabile che sia criptata (o compressa in qualche modo).

Inoltre, puoi utilizzare questi strumenti per estrarre **file incorporati nel firmware**:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Oppure [**binvis.io**](https://binvis.io/#/) ([codice](https://code.google.com/archive/p/binvis/)) per ispezionare il file.

### Ottenere il Filesystem

Con gli strumenti precedentemente menzionati come `binwalk -ev <bin>`, dovresti essere in grado di **estrarre il filesystem**.\
Di solito, Binwalk lo estrae all'interno di una **cartella con il nome del tipo di filesystem**, che di solito è uno tra i seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Estrazione Manuale del Filesystem

A volte, binwalk **non ha il byte magico del filesystem nelle sue firme**. In questi casi, utilizza binwalk per **trovare l'offset del filesystem e intagliare il filesystem compresso** dal binario ed **estrarre manualmente** il filesystem in base al suo tipo utilizzando i seguenti passaggi.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Esegui il seguente **comando dd** per estrarre il filesystem Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

In alternativa, potrebbe essere eseguito anche il seguente comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Per squashfs (usato nell'esempio sopra)

`$ unsquashfs dir.squashfs`

I file saranno nella directory "`squashfs-root`" successivamente.

* File di archivio CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Per i filesystem jffs2

`$ jefferson rootfsfile.jffs2`

* Per i filesystem ubifs con flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisi del firmware

Una volta ottenuto il firmware, è essenziale analizzarlo per comprendere la sua struttura e le potenziali vulnerabilità. Questo processo prevede l'utilizzo di vari strumenti per analizzare ed estrarre dati preziosi dall'immagine del firmware.

### Strumenti di analisi iniziale

Viene fornito un insieme di comandi per l'ispezione iniziale del file binario (denominato `<bin>`). Questi comandi aiutano a identificare i tipi di file, estrarre stringhe, analizzare dati binari e comprendere i dettagli delle partizioni e dei filesystem:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Per valutare lo stato di crittografia dell'immagine, viene controllata l'**entropia** con `binwalk -E <bin>`. Un'entropia bassa suggerisce una mancanza di crittografia, mentre un'entropia alta indica una possibile crittografia o compressione.

Per estrarre i **file incorporati**, si consiglia di utilizzare strumenti e risorse come la documentazione di **file-data-carving-recovery-tools** e **binvis.io** per l'ispezione dei file.

### Estrazione del Filesystem

Utilizzando `binwalk -ev <bin>`, di solito è possibile estrarre il filesystem, spesso in una directory con il nome del tipo di filesystem (ad esempio, squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di filesystem a causa della mancanza di magic bytes, è necessaria un'estrazione manuale. Ciò comporta l'utilizzo di `binwalk` per individuare l'offset del filesystem, seguito dal comando `dd` per estrarre il filesystem:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Successivamente, a seconda del tipo di filesystem (ad esempio, squashfs, cpio, jffs2, ubifs), vengono utilizzati comandi diversi per estrarre manualmente i contenuti.

### Analisi del Filesystem

Una volta estratto il filesystem, inizia la ricerca di vulnerabilità di sicurezza. Si presta attenzione a demoni di rete non sicuri, credenziali codificate, endpoint API, funzionalità del server di aggiornamento, codice non compilato, script di avvio e binari compilati per l'analisi offline.

Le **posizioni chiave** e gli **elementi** da ispezionare includono:

* **etc/shadow** e **etc/passwd** per le credenziali degli utenti
* Certificati SSL e chiavi in **etc/ssl**
* File di configurazione e script per potenziali vulnerabilità
* Binari incorporati per ulteriori analisi
* Comuni server web e binari per dispositivi IoT

Diversi strumenti aiutano a scoprire informazioni sensibili e vulnerabilità all'interno del filesystem:

* [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per la ricerca di informazioni sensibili
* [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core) per un'analisi completa del firmware
* [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) e [**EMBA**](https://github.com/e-m-b-a/emba) per l'analisi statica e dinamica

### Verifiche di sicurezza sui binari compilati

Sia il codice sorgente che i binari compilati trovati nel filesystem devono essere esaminati per individuare vulnerabilità. Strumenti come **checksec.sh** per i binari Unix e **PESecurity** per i binari Windows aiutano a identificare binari non protetti che potrebbero essere sfruttati.

## Emulazione del Firmware per l'Analisi Dinamica

Il processo di emulazione del firmware consente l'**analisi dinamica** del funzionamento di un dispositivo o di un singolo programma. Questo approccio può incontrare sfide legate alle dipendenze hardware o architetturali, ma il trasferimento del filesystem di root o di binari specifici su un dispositivo con architettura e endianness corrispondenti, come un Raspberry Pi, o su una macchina virtuale pre-costruita, può facilitare ulteriori test.

### Emulazione di Singoli Binari

Per esaminare singoli programmi, è fondamentale identificare l'endianness e l'architettura della CPU del programma.

#### Esempio con Architettura MIPS

Per emulare un binario con architettura MIPS, è possibile utilizzare il comando:

```bash
file ./squashfs-root/bin/busybox
```

E per installare gli strumenti di emulazione necessari:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Per MIPS (big-endian), viene utilizzato `qemu-mips`, mentre per i binari little-endian, la scelta ricade su `qemu-mipsel`.

#### Emulazione dell'architettura ARM

Per i binari ARM, il processo è simile, con l'emulatore `qemu-arm` utilizzato per l'emulazione.

### Emulazione del sistema completo

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e altri, facilitano l'emulazione completa del firmware, automatizzando il processo e aiutando nell'analisi dinamica.

## Analisi dinamica nella pratica

In questa fase, viene utilizzato un ambiente di dispositivo reale o emulato per l'analisi. È essenziale mantenere l'accesso alla shell del sistema operativo e al filesystem. L'emulazione potrebbe non riprodurre perfettamente le interazioni hardware, rendendo necessari riavvii occasionali dell'emulazione. L'analisi dovrebbe esaminare nuovamente il filesystem, sfruttare le pagine web e i servizi di rete esposti ed esplorare le vulnerabilità del bootloader. I test di integrità del firmware sono fondamentali per identificare potenziali vulnerabilità di backdoor.

## Tecniche di analisi in tempo reale

L'analisi in tempo reale comporta l'interazione con un processo o un binario nel suo ambiente operativo, utilizzando strumenti come gdb-multiarch, Frida e Ghidra per impostare punti di interruzione e identificare vulnerabilità attraverso fuzzing e altre tecniche.

## Sfruttamento binario e proof-of-concept

Lo sviluppo di un PoC per le vulnerabilità identificate richiede una profonda comprensione dell'architettura di destinazione e della programmazione in linguaggi di basso livello. Le protezioni binarie in tempo di esecuzione nei sistemi embedded sono rare, ma quando presenti, potrebbero essere necessarie tecniche come la programmazione orientata al ritorno (ROP).

## Sistemi operativi preparati per l'analisi del firmware

Sistemi operativi come [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) forniscono ambienti preconfigurati per il testing della sicurezza del firmware, dotati degli strumenti necessari.

## Sistemi operativi preparati per analizzare il firmware

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distribuzione progettata per aiutarti a eseguire valutazioni di sicurezza e penetration testing dei dispositivi Internet of Things (IoT). Ti fa risparmiare molto tempo fornendo un ambiente preconfigurato con tutti gli strumenti necessari caricati.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo per il testing della sicurezza embedded basato su Ubuntu 18.04 pre-caricato con strumenti per il testing della sicurezza del firmware.

## Firmware vulnerabili per esercitarsi

Per esercitarsi nella scoperta di vulnerabilità nel firmware, utilizzare i seguenti progetti di firmware vulnerabili come punto di partenza.

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* The Damn Vulnerable Router Firmware Project
* [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
* Damn Vulnerable ARM Router (DVAR)
* [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
* ARM-X
* [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
* Azeria Labs VM 2.0
* [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
* Damn Vulnerable IoT Device (DVID)
* [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Riferimenti

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Formazione e certificazione

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
