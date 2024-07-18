{% hint style="success" %}
Impara e pratica l'hacking di AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'hacking di GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}


# Strumenti di Carving

## Autopsy

Lo strumento più comune utilizzato in informatica forense per estrarre file dalle immagini è [**Autopsy**](https://www.autopsy.com/download/). Scaricalo, installalo e fallo analizzare il file per trovare file "nascosti". Nota che Autopsy è progettato per supportare immagini di disco e altri tipi di immagini, ma non file semplici.

## Binwalk <a id="binwalk"></a>

**Binwalk** è uno strumento per cercare file binari come immagini e file audio per file e dati incorporati.
Può essere installato con `apt`, tuttavia la [fonte](https://github.com/ReFirmLabs/binwalk) può essere trovata su github.
**Comandi utili**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Un altro strumento comune per trovare file nascosti è **foremost**. Puoi trovare il file di configurazione di foremost in `/etc/foremost.conf`. Se desideri cercare solo alcuni file specifici, rimuovine il commento. Se non rimuovi il commento da nulla, foremost cercherà i tipi di file configurati per impostazione predefinita.
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

Questo strumento è incluso in kali ma puoi trovarlo qui: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Questo strumento può esaminare un'immagine e **estrarre pcaps** al suo interno, **informazioni di rete \(URL, domini, IP, MAC, email\)** e altri **file**. Devi solo fare:
```text
bulk_extractor memory.img -o out_folder
```
Naviga attraverso **tutte le informazioni** che lo strumento ha raccolto \(password?\), **analizza** i **pacchetti** \(leggi [**Analisi Pcaps**](../pcap-inspection/)\), cerca **domini strani** \(domini correlati al **malware** o **inesistenti**\).

## PhotoRec

Puoi trovarlo su [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Viene fornito con una versione GUI e CLI. Puoi selezionare i **tipi di file** che desideri far cercare a PhotoRec.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Strumenti Specifici per il Carving dei Dati

## FindAES

Cerca chiavi AES cercando i loro programmi di chiavi. In grado di trovare chiavi a 128, 192 e 256 bit, come quelle utilizzate da TrueCrypt e BitLocker.

Scarica [qui](https://sourceforge.net/projects/findaes/).

# Strumenti complementari

Puoi utilizzare [**viu** ](https://github.com/atanunq/viu)per visualizzare immagini dal terminale.
Puoi utilizzare lo strumento della riga di comando di Linux **pdftotext** per trasformare un pdf in testo e leggerlo.
