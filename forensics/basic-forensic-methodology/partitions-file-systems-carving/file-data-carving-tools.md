<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su github.

</details>


# Strumenti di Carving

## Autopsy

Lo strumento più comune utilizzato in forense per estrarre file dalle immagini è [**Autopsy**](https://www.autopsy.com/download/). Scaricalo, installalo e fai in modo che ingesti il file per trovare file "nascosti". Nota che Autopsy è progettato per supportare immagini di disco e altri tipi di immagini, ma non file semplici.

## Binwalk <a id="binwalk"></a>

**Binwalk** è uno strumento per cercare file binari come immagini e file audio per file e dati incorporati.
Può essere installato con `apt`, tuttavia il [codice sorgente](https://github.com/ReFirmLabs/binwalk) può essere trovato su github.
**Comandi utili**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Un altro strumento comune per trovare file nascosti è **foremost**. Puoi trovare il file di configurazione di foremost in `/etc/foremost.conf`. Se desideri cercare solo alcuni file specifici, rimuovi il commento. Se non rimuovi il commento, foremost cercherà i tipi di file configurati di default.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** è un altro strumento che può essere utilizzato per trovare ed estrarre **file incorporati in un file**. In questo caso sarà necessario rimuovere il commento dal file di configurazione \(_/etc/scalpel/scalpel.conf_\) dei tipi di file che si desidera estrarre.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Questo strumento è incluso in Kali, ma puoi trovarlo qui: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Questo strumento può scansionare un'immagine e **estrarre pcaps** al suo interno, **informazioni di rete (URL, domini, IP, MAC, email)** e altri **file**. Devi solo eseguire:
```text
bulk_extractor memory.img -o out_folder
```
Esplora **tutte le informazioni** che lo strumento ha raccolto \(password?\), **analizza** i **pacchetti** \(leggi [**Analisi Pcaps**](../pcap-inspection/)\), cerca **domini strani** \(domini correlati a **malware** o **inesistenti**\).

## PhotoRec

Puoi trovarlo su [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Viene fornito con una versione GUI e CLI. Puoi selezionare i **tipi di file** che desideri che PhotoRec cerchi.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Strumenti specifici per il recupero dei dati

## FindAES

Cerca le chiavi AES cercando i loro programmi di chiavi. In grado di trovare chiavi a 128, 192 e 256 bit, come quelle utilizzate da TrueCrypt e BitLocker.

Scarica [qui](https://sourceforge.net/projects/findaes/).

# Strumenti complementari

Puoi utilizzare [**viu** ](https://github.com/atanunq/viu)per visualizzare immagini dal terminale.
Puoi utilizzare lo strumento della riga di comando di Linux **pdftotext** per trasformare un pdf in testo e leggerlo.



<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
