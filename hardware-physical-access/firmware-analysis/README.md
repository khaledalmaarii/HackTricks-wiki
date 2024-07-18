# Analisi del Firmware

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
{% endhint %}

## **Introduzione**

Il firmware è un software essenziale che consente ai dispositivi di funzionare correttamente gestendo e facilitando la comunicazione tra i componenti hardware e il software con cui gli utenti interagiscono. È memorizzato in memoria permanente, garantendo che il dispositivo possa accedere istruzioni vitali dal momento in cui viene acceso, portando al lancio del sistema operativo. Esaminare e potenzialmente modificare il firmware è un passo critico per identificare vulnerabilità di sicurezza.

## **Raccolta di Informazioni**

La **raccolta di informazioni** è un passo iniziale critico per comprendere la composizione di un dispositivo e le tecnologie che utilizza. Questo processo coinvolge la raccolta di dati su:

* L'architettura della CPU e il sistema operativo che esegue
* Specifiche del bootloader
* Layout hardware e datasheet
* Metriche del codice sorgente e posizioni
* Librerie esterne e tipi di licenza
* Storico degli aggiornamenti e certificazioni regolamentari
* Diagrammi architetturali e di flusso
* Valutazioni della sicurezza e vulnerabilità identificate

A tale scopo, gli strumenti di **intelligence open-source (OSINT)** sono preziosi, così come l'analisi di eventuali componenti software open-source disponibili attraverso processi di revisione manuali e automatizzati. Strumenti come [Coverity Scan](https://scan.coverity.com) e [LGTM di Semmle](https://lgtm.com/#explore) offrono analisi statica gratuita che può essere sfruttata per individuare potenziali problemi.

## **Acquisizione del Firmware**

L'ottenimento del firmware può essere affrontato attraverso vari mezzi, ognuno con il proprio livello di complessità:

* **Direttamente** dalla fonte (sviluppatori, produttori)
* **Costruendolo** seguendo le istruzioni fornite
* **Scaricandolo** dai siti di supporto ufficiali
* Utilizzando **query Google dork** per trovare file firmware ospitati
* Accedendo direttamente allo **storage cloud**, con strumenti come [S3Scanner](https://github.com/sa7mon/S3Scanner)
* Intercettando **aggiornamenti** tramite tecniche di man-in-the-middle
* **Estrazione** dal dispositivo tramite connessioni come **UART**, **JTAG**, o **PICit**
* **Sniffing** per le richieste di aggiornamento all'interno della comunicazione del dispositivo
* Identificare e utilizzare **punti finali di aggiornamento codificati**
* **Dumping** dal bootloader o dalla rete
* **Rimuovendo e leggendo** il chip di memorizzazione, quando tutto il resto fallisce, utilizzando gli strumenti hardware appropriati

## Analisi del firmware

Ora che **hai il firmware**, devi estrarre informazioni su di esso per sapere come trattarlo. Diversi strumenti che puoi utilizzare per questo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se non trovi molto con quegli strumenti, controlla l'**entropia** dell'immagine con `binwalk -E <bin>`, se l'entropia è bassa, allora è improbabile che sia criptata. Se l'entropia è alta, è probabile che sia criptata (o compressa in qualche modo).

Inoltre, puoi utilizzare questi strumenti per estrarre **file incorporati nel firmware**:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Oppure [**binvis.io**](https://binvis.io/#/) ([codice](https://code.google.com/archive/p/binvis/)) per ispezionare il file.

### Ottenere il File System

Con gli strumenti precedentemente commentati come `binwalk -ev <bin>` dovresti essere in grado di **estrarre il filesystem**.\
Di solito, Binwalk lo estrae all'interno di una **cartella denominata come il tipo di filesystem**, che di solito è uno tra i seguenti: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Estrazione Manuale del File System

A volte, binwalk **non avrà il byte magico del filesystem nelle sue firme**. In questi casi, utilizza binwalk per **trovare l'offset del filesystem e intagliare il filesystem compresso** dal binario ed **estrarre manualmente** il filesystem in base al suo tipo seguendo i passaggi seguenti.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Esegui il seguente **comando dd** intagliando il filesystem Squashfs.
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

## Analisi del Firmware

Una volta ottenuto il firmware, è essenziale dissezionarlo per comprendere la sua struttura e le potenziali vulnerabilità. Questo processo coinvolge l'utilizzo di vari strumenti per analizzare ed estrarre dati preziosi dall'immagine del firmware.

### Strumenti di Analisi Iniziale

Viene fornito un insieme di comandi per l'ispezione iniziale del file binario (indicato come `<bin>`). Questi comandi aiutano nell'identificare i tipi di file, estrarre stringhe, analizzare dati binari e comprendere i dettagli delle partizioni e dei filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Per valutare lo stato di crittografia dell'immagine, l'**entropia** viene verificata con `binwalk -E <bin>`. Un'entropia bassa suggerisce una mancanza di crittografia, mentre un'entropia alta indica una possibile crittografia o compressione.

Per estrarre **file incorporati**, sono consigliati strumenti e risorse come la documentazione di **file-data-carving-recovery-tools** e **binvis.io** per l'ispezione dei file.

### Estrazione del File System

Utilizzando `binwalk -ev <bin>`, di solito è possibile estrarre il file system, spesso in una directory denominata come il tipo di file system (ad esempio, squashfs, ubifs). Tuttavia, quando **binwalk** non riesce a riconoscere il tipo di file system a causa della mancanza di byte magici, è necessaria un'estrazione manuale. Ciò comporta l'utilizzo di `binwalk` per individuare l'offset del file system, seguito dal comando `dd` per estrarre il file system:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
### Analisi del Filesystem

Con il filesystem estratto, inizia la ricerca di difetti di sicurezza. Si presta attenzione ai daemon di rete non sicuri, alle credenziali codificate, agli endpoint API, alle funzionalità del server di aggiornamento, al codice non compilato, agli script di avvio e ai binari compilati per l'analisi offline.

**Posizioni chiave** e **elementi** da ispezionare includono:

- **etc/shadow** e **etc/passwd** per le credenziali utente
- Certificati SSL e chiavi in **etc/ssl**
- File di configurazione e script per potenziali vulnerabilità
- Binari incorporati per ulteriori analisi
- Comuni server web per dispositivi IoT e binari

Diversi strumenti aiutano a scoprire informazioni sensibili e vulnerabilità all'interno del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) per la ricerca di informazioni sensibili
- [**Lo strumento di analisi e confronto del firmware (FACT)**](https://github.com/fkie-cad/FACT\_core) per un'analisi completa del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) e [**EMBA**](https://github.com/e-m-b-a/emba) per analisi statiche e dinamiche

### Controlli di Sicurezza sui Binari Compilati

Sia il codice sorgente che i binari compilati trovati nel filesystem devono essere esaminati per individuare vulnerabilità. Strumenti come **checksec.sh** per i binari Unix e **PESecurity** per i binari Windows aiutano a identificare binari non protetti che potrebbero essere sfruttati.

## Emulazione del Firmware per l'Analisi Dinamica

Il processo di emulazione del firmware consente l'**analisi dinamica** dell'operazione di un dispositivo o di un singolo programma. Questo approccio può incontrare sfide legate alle dipendenze hardware o architetturali, ma il trasferimento del filesystem radice o di binari specifici su un dispositivo con architettura e endianness corrispondenti, come un Raspberry Pi, o su una macchina virtuale pre-costruita, può facilitare ulteriori test.

### Emulazione di Singoli Binari

Per esaminare singoli programmi, è cruciale identificare l'endianness e l'architettura della CPU del programma.

#### Esempio con Architettura MIPS

Per emulare un binario con architettura MIPS, è possibile utilizzare il comando:
```bash
file ./squashfs-root/bin/busybox
```
E per installare gli strumenti di emulazione necessari:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
### Emulazione dell'Architettura ARM

Per i binari ARM, il processo è simile, con l'emulatore `qemu-arm` utilizzato per l'emulazione.

### Emulazione del Sistema Completo

Strumenti come [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e altri facilitano l'emulazione completa del firmware, automatizzando il processo e aiutando nell'analisi dinamica.

## Analisi Dinamica nella Pratica

In questa fase, viene utilizzato un ambiente dispositivo reale o emulato per l'analisi. È essenziale mantenere l'accesso alla shell del sistema operativo e al filesystem. L'emulazione potrebbe non replicare perfettamente le interazioni hardware, rendendo necessari riavvii occasionali dell'emulazione. L'analisi dovrebbe esaminare nuovamente il filesystem, sfruttare le pagine web esposte e i servizi di rete, ed esplorare le vulnerabilità del bootloader. I test di integrità del firmware sono fondamentali per identificare potenziali vulnerabilità backdoor.

## Tecniche di Analisi in Esecuzione

L'analisi in esecuzione coinvolge l'interazione con un processo o un binario nel suo ambiente operativo, utilizzando strumenti come gdb-multiarch, Frida e Ghidra per impostare i punti di interruzione e identificare vulnerabilità attraverso fuzzing e altre tecniche.

## Sfruttamento Binario e Proof-of-Concept

Lo sviluppo di un PoC per le vulnerabilità identificate richiede una profonda comprensione dell'architettura di destinazione e della programmazione in linguaggi di basso livello. Le protezioni di runtime binario nei sistemi embedded sono rare, ma quando presenti, potrebbero essere necessarie tecniche come Return Oriented Programming (ROP).

## Sistemi Operativi Preparati per l'Analisi del Firmware

Sistemi operativi come [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) forniscono ambienti preconfigurati per i test di sicurezza del firmware, dotati degli strumenti necessari.

## Sistemi Operativi Preparati per Analizzare il Firmware

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS è una distribuzione progettata per aiutarti a eseguire valutazioni di sicurezza e test di penetrazione dei dispositivi Internet of Things (IoT). Ti fa risparmiare molto tempo fornendo un ambiente preconfigurato con tutti gli strumenti necessari caricati.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo per test di sicurezza embedded basato su Ubuntu 18.04 pre-caricato con strumenti di test di sicurezza del firmware.

## Firmware Vulnerabili per Esercitarsi

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

## Formazione e Certificazione

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)
