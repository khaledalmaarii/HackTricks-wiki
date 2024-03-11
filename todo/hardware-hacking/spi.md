<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>


# Informazioni di Base

SPI (Serial Peripheral Interface) è un Protocollo di Comunicazione Seriale Sincrono utilizzato nei sistemi embedded per la comunicazione a breve distanza tra IC (Circuiti Integrati). Il Protocollo di Comunicazione SPI fa uso dell'architettura master-slave che è orchestrata dal Segnale di Clock e Chip Select. Un'architettura master-slave consiste di un master (di solito un microprocessore) che gestisce periferiche esterne come EEPROM, sensori, dispositivi di controllo, ecc. che sono considerati come gli slave.

Più slave possono essere collegati a un master ma gli slave non possono comunicare tra loro. Gli slave sono amministrati da due pin, clock e chip select. Poiché SPI è un protocollo di comunicazione sincrono, i pin di input e output seguono i segnali di clock. Il chip select è utilizzato dal master per selezionare uno slave e interagire con esso. Quando il chip select è alto, il dispositivo slave non è selezionato mentre quando è basso, il chip è stato selezionato e il master interagirà con lo slave.

Il MOSI (Master Out, Slave In) e il MISO (Master In, Slave Out) sono responsabili dell'invio e della ricezione dei dati. I dati vengono inviati al dispositivo slave attraverso il pin MOSI mentre il chip select è mantenuto basso. I dati di input contengono istruzioni, indirizzi di memoria o dati secondo il datasheet del fornitore del dispositivo slave. Dopo un input valido, il pin MISO è responsabile della trasmissione dei dati al master. I dati di output vengono inviati esattamente al ciclo di clock successivo dopo la fine dell'input. Il pin MISO trasmette dati fino a quando i dati vengono completamente trasmessi o il master imposta il pin chip select alto (in tal caso, lo slave smetterebbe di trasmettere e il master non ascolterebbe dopo quel ciclo di clock).

# Dump Flash

## Bus Pirate + flashrom

![](<../../.gitbook/assets/image (201).png>)

Si noti che anche se il PINOUT del Pirate Bus indica pin per **MOSI** e **MISO** da collegare a SPI, alcuni SPI possono indicare i pin come DI e DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (648) (1) (1).png>)

In Windows o Linux è possibile utilizzare il programma [**`flashrom`**](https://www.flashrom.org/Flashrom) per eseguire il dump del contenuto della memoria flash eseguendo qualcosa del genere:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di Github.

</details>
