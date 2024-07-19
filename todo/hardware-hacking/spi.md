# SPI

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Informazioni di base

SPI (Serial Peripheral Interface) è un protocollo di comunicazione seriale sincrono utilizzato nei sistemi embedded per la comunicazione a breve distanza tra IC (Circuiti Integrati). Il protocollo di comunicazione SPI utilizza un'architettura master-slave orchestrata dal segnale di clock e dal segnale di selezione del chip. Un'architettura master-slave consiste in un master (di solito un microprocessore) che gestisce periferiche esterne come EEPROM, sensori, dispositivi di controllo, ecc., considerati come schiavi.

Più schiavi possono essere collegati a un master, ma gli schiavi non possono comunicare tra loro. Gli schiavi sono gestiti da due pin, clock e selezione del chip. Poiché SPI è un protocollo di comunicazione sincrono, i pin di input e output seguono i segnali di clock. La selezione del chip è utilizzata dal master per selezionare uno schiavo e interagire con esso. Quando la selezione del chip è alta, il dispositivo schiavo non è selezionato, mentre quando è bassa, il chip è stato selezionato e il master interagirà con lo schiavo.

Il MOSI (Master Out, Slave In) e il MISO (Master In, Slave Out) sono responsabili dell'invio e della ricezione dei dati. I dati vengono inviati al dispositivo schiavo tramite il pin MOSI mentre la selezione del chip è mantenuta bassa. I dati di input contengono istruzioni, indirizzi di memoria o dati secondo il datasheet del fornitore del dispositivo schiavo. Dopo un input valido, il pin MISO è responsabile della trasmissione dei dati al master. I dati di output vengono inviati esattamente al ciclo di clock successivo dopo la fine dell'input. I pin MISO trasmettono i dati fino a quando i dati non sono completamente trasmessi o il master imposta il pin di selezione del chip alto (in tal caso, lo schiavo smetterebbe di trasmettere e il master non ascolterebbe dopo quel ciclo di clock).

## Dumping del firmware da EEPROM

Dumping del firmware può essere utile per analizzare il firmware e trovare vulnerabilità in esso. Spesso, il firmware non è disponibile su Internet o è irrilevante a causa di variazioni di fattori come numero di modello, versione, ecc. Pertanto, estrarre il firmware direttamente dal dispositivo fisico può essere utile per essere specifici nella ricerca di minacce.

Ottenere la console seriale può essere utile, ma spesso accade che i file siano di sola lettura. Questo limita l'analisi per vari motivi. Ad esempio, gli strumenti necessari per inviare e ricevere pacchetti potrebbero non essere presenti nel firmware. Quindi, estrarre i binari per reverse engineering non è fattibile. Pertanto, avere l'intero firmware dumpato sul sistema ed estrarre i binari per l'analisi può essere molto utile.

Inoltre, durante il red teaming e l'accesso fisico ai dispositivi, dumpare il firmware può aiutare a modificare i file o iniettare file dannosi e poi riflasharli nella memoria, il che potrebbe essere utile per impiantare una backdoor nel dispositivo. Pertanto, ci sono numerose possibilità che possono essere sbloccate con il dumping del firmware.

### Programmatore e lettore EEPROM CH341A

Questo dispositivo è uno strumento economico per dumpare firmware da EEPROM e anche riflasharli con file di firmware. Questa è stata una scelta popolare per lavorare con chip BIOS dei computer (che sono solo EEPROM). Questo dispositivo si collega tramite USB e richiede strumenti minimi per iniziare. Inoltre, di solito completa il compito rapidamente, quindi può essere utile anche per l'accesso fisico ai dispositivi.

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

Collegare la memoria EEPROM con il programmatore CH341a e collegare il dispositivo al computer. Nel caso in cui il dispositivo non venga rilevato, provare a installare i driver nel computer. Inoltre, assicurarsi che l'EEPROM sia collegata nella giusta orientazione (di solito, posizionare il pin VCC in orientamento inverso rispetto al connettore USB) altrimenti il software non sarà in grado di rilevare il chip. Fare riferimento al diagramma se necessario:

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

Infine, utilizzare software come flashrom, G-Flash (GUI), ecc. per dumpare il firmware. G-Flash è uno strumento GUI minimale, veloce e rileva automaticamente l'EEPROM. Questo può essere utile se il firmware deve essere estratto rapidamente, senza troppa manipolazione della documentazione.

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

Dopo aver dumpato il firmware, l'analisi può essere effettuata sui file binari. Strumenti come strings, hexdump, xxd, binwalk, ecc. possono essere utilizzati per estrarre molte informazioni sul firmware e sull'intero file system.

Per estrarre i contenuti dal firmware, può essere utilizzato binwalk. Binwalk analizza le firme esadecimali e identifica i file nel file binario ed è in grado di estrarli.
```
binwalk -e <filename>
```
Il può essere .bin o .rom a seconda degli strumenti e delle configurazioni utilizzate.

{% hint style="danger" %}
Nota che l'estrazione del firmware è un processo delicato e richiede molta pazienza. Qualsiasi maneggiamento errato può potenzialmente corrompere il firmware o addirittura cancellarlo completamente e rendere il dispositivo inutilizzabile. Si consiglia di studiare il dispositivo specifico prima di tentare di estrarre il firmware.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Nota che anche se il PINOUT del Pirate Bus indica pin per **MOSI** e **MISO** per connettersi a SPI, alcuni SPI possono indicare pin come DI e DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

In Windows o Linux puoi usare il programma [**`flashrom`**](https://www.flashrom.org/Flashrom) per dumpare il contenuto della memoria flash eseguendo qualcosa come:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{% hint style="success" %}
Impara e pratica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
