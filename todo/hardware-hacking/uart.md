# UART

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale di WhiteIntel è contrastare le violazioni degli account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi controllare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

***

## Informazioni di Base

UART è un protocollo seriale, il che significa che trasferisce i dati tra i componenti un bit alla volta. Al contrario, i protocolli di comunicazione parallela trasmettono i dati simultaneamente attraverso più canali. I protocolli seriali comuni includono RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express e USB.

Generalmente, la linea viene mantenuta alta (a un valore logico 1) mentre UART è nello stato di inattività. Quindi, per segnalare l'inizio di un trasferimento dati, il trasmettitore invia un bit di start al ricevitore, durante il quale il segnale viene mantenuto basso (a un valore logico 0). Successivamente, il trasmettitore invia cinque otto bit di dati contenenti il messaggio effettivo, seguiti da un bit di parità opzionale e uno o due bit di stop (con un valore logico 1), a seconda della configurazione. Il bit di parità, utilizzato per il controllo degli errori, è raramente visto in pratica. Il bit di stop (o i bit) indicano la fine della trasmissione.

Chiamiamo la configurazione più comune 8N1: otto bit di dati, nessuna parità e un bit di stop. Ad esempio, se volessimo inviare il carattere C, o 0x43 in ASCII, in una configurazione UART 8N1, invieremmo i seguenti bit: 0 (il bit di start); 0, 1, 0, 0, 0, 0, 1, 1 (il valore di 0x43 in binario), e 0 (il bit di stop).

![](<../../.gitbook/assets/image (764).png>)

Strumenti hardware per comunicare con UART:

* Adattatore USB-seriale
* Adattatori con chip CP2102 o PL2303
* Strumento multipurpose come: Bus Pirate, l'Adafruit FT232H, lo Shikra o l'Attify Badge

### Identificazione delle Porte UART

UART ha 4 porte: **TX**(Trasmetti), **RX**(Ricevi), **Vcc**(Tensione) e **GND**(Terra). Potresti trovare 4 porte con le lettere **`TX`** e **`RX`** **scritte** sulla PCB. Ma se non c'è alcuna indicazione, potresti dover cercare di trovarle tu stesso utilizzando un **multimetro** o un **analizzatore logico**.

Con un **multimetro** e il dispositivo spento:

* Per identificare il pin **GND** utilizza la modalità **Test di continuità**, posiziona il morsetto posteriore a terra e testa con quello rosso fino a sentire un suono dal multimetro. Sulla PCB possono essere presenti diversi pin GND, quindi potresti aver trovato o meno quello appartenente a UART.
* Per identificare la porta **VCC**, imposta la modalità **tensione DC** e impostala fino a 20 V di tensione. Morsetto nero a terra e morsetto rosso sul pin. Accendi il dispositivo. Se il multimetro misura una tensione costante di 3,3 V o 5 V, hai trovato il pin Vcc. Se ottieni altre tensioni, riprova con altre porte.
* Per identificare la porta **TX**, **modalità tensione DC** fino a 20 V di tensione, morsetto nero a terra e morsetto rosso sul pin, e accendi il dispositivo. Se trovi che la tensione fluttua per alcuni secondi e poi si stabilizza al valore di Vcc, hai molto probabilmente trovato la porta TX. Questo perché quando si accende, invia alcuni dati di debug.
* La porta **RX** sarebbe la più vicina alle altre 3, ha la minore fluttuazione di tensione e il valore complessivo più basso di tutti i pin UART.

Puoi confondere i pin TX e RX e non succederebbe nulla, ma se confondi il pin GND e il pin VCC potresti bruciare il circuito.

In alcuni dispositivi target, la porta UART è disabilitata dal produttore disabilitando RX o TX o addirittura entrambi. In tal caso, può essere utile tracciare le connessioni nella scheda del circuito e trovare un punto di breakout. Un forte suggerimento per confermare la mancata rilevazione di UART e la rottura del circuito è controllare la garanzia del dispositivo. Se il dispositivo è stato spedito con una qualche garanzia, il produttore lascia alcune interfacce di debug (in questo caso, UART) e quindi, deve aver scollegato l'UART e lo riattaccherebbe durante il debug. Questi pin di breakout possono essere collegati saldando o con fili jumper.

### Identificazione del Baud Rate UART

Il modo più semplice per identificare il baud rate corretto è guardare l'**output del pin TX e provare a leggere i dati**. Se i dati che ricevi non sono leggibili, passa al prossimo baud rate possibile fino a quando i dati diventano leggibili. Puoi utilizzare un adattatore USB-seriale o un dispositivo multipurpose come Bus Pirate per fare ciò, abbinato a uno script di aiuto, come [baudrate.py](https://github.com/devttys0/baudrate/). I baud rate più comuni sono 9600, 38400, 19200, 57600 e 115200.

{% hint style="danger" %}
È importante notare che in questo protocollo è necessario collegare il TX di un dispositivo al RX dell'altro!
{% endhint %}

## Adattatore UART CP210X a TTY

Il Chip CP210X è utilizzato in molti prototipi come NodeMCU (con esp8266) per la comunicazione seriale. Questi adattatori sono relativamente economici e possono essere utilizzati per connettersi all'interfaccia UART del target. Il dispositivo ha 5 pin: 5V, GND, RXD, TXD, 3.3V. Assicurati di collegare la tensione supportata dal target per evitare danni. Infine, collega il pin RXD dell'Adattatore al TXD del target e il pin TXD dell'Adattatore al RXD del target.

Nel caso in cui l'adattatore non venga rilevato, assicurati che i driver CP210X siano installati nel sistema host. Una volta che l'adattatore viene rilevato e collegato, possono essere utilizzati strumenti come picocom, minicom o screen.

Per elencare i dispositivi collegati ai sistemi Linux/MacOS:
```
ls /dev/
```
Per interagire in modo basilare con l'interfaccia UART, utilizza il seguente comando:
```
picocom /dev/<adapter> --baud <baudrate>
```
Per minicom, utilizza il seguente comando per configurarlo:
```
minicom -s
```
Configura le impostazioni come il baudrate e il nome del dispositivo nell'opzione `Impostazioni della porta seriale`.

Dopo la configurazione, utilizza il comando `minicom` per avviare la Console UART.

## UART tramite Arduino UNO R3 (schede chip Atmel 328p rimovibili)

Nel caso in cui gli adattatori UART Serial to USB non siano disponibili, è possibile utilizzare Arduino UNO R3 con un rapido hack. Poiché Arduino UNO R3 è di solito disponibile ovunque, questo può risparmiare molto tempo.

Arduino UNO R3 ha un adattatore USB a seriale integrato sulla scheda stessa. Per ottenere la connessione UART, basta staccare il chip microcontrollore Atmel 328p dalla scheda. Questo hack funziona su varianti di Arduino UNO R3 che non hanno saldato il chip Atmel 328p sulla scheda (viene utilizzata la versione SMD). Collega il pin RX di Arduino (Pin digitale 0) al pin TX dell'interfaccia UART e il pin TX di Arduino (Pin digitale 1) al pin RX dell'interfaccia UART.

Infine, è consigliabile utilizzare Arduino IDE per ottenere la Console Seriale. Nella sezione `strumenti` nel menu, seleziona l'opzione `Console Seriale` e imposta il baud rate in base all'interfaccia UART.

## Bus Pirate

In questo scenario andremo a intercettare la comunicazione UART dell'Arduino che sta inviando tutte le stampe del programma al Monitor Seriale.
```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
## Dumping Firmware con la Console UART

La Console UART fornisce un ottimo modo per lavorare con il firmware sottostante nell'ambiente di runtime. Ma quando l'accesso alla Console UART è in sola lettura, potrebbe introdurre molti vincoli. In molti dispositivi embedded, il firmware è memorizzato in EEPROM e eseguito in processori che hanno memoria volatile. Pertanto, il firmware viene mantenuto in sola lettura poiché il firmware originale durante la produzione è all'interno della stessa EEPROM e qualsiasi nuovo file verrebbe perso a causa della memoria volatile. Pertanto, il dump del firmware è uno sforzo prezioso durante il lavoro con i firmware embedded.

Ci sono molti modi per farlo e la sezione SPI copre metodi per estrarre il firmware direttamente dalla EEPROM con vari dispositivi. Anche se è consigliabile provare prima a fare il dump del firmware con UART poiché fare il dump del firmware con dispositivi fisici e interazioni esterne può essere rischioso.

Il dump del firmware dalla Console UART richiede prima di tutto di ottenere l'accesso ai bootloader. Molti fornitori popolari utilizzano uboot (Universal Bootloader) come loro bootloader per caricare Linux. Pertanto, è necessario ottenere l'accesso a uboot.

Per ottenere l'accesso al bootloader, collegare la porta UART al computer e utilizzare uno qualsiasi degli strumenti Serial Console e mantenere disconnesso l'alimentatore del dispositivo. Una volta che la configurazione è pronta, premere il tasto Invio e tenerlo premuto. Infine, collegare l'alimentatore al dispositivo e lasciarlo avviare.

Fare ciò interromperà uboot dal caricamento e fornirà un menu. È consigliabile comprendere i comandi di uboot e utilizzare il menu di aiuto per elencarli. Questo potrebbe essere il comando `help`. Poiché i diversi fornitori utilizzano diverse configurazioni, è necessario capirle separatamente.

Di solito, il comando per fare il dump del firmware è:
```
md
```
Il termine "memory dump" sta per "dump di memoria". Questo dump della memoria (Contenuto dell'EEPROM) verrà visualizzato sullo schermo. Si consiglia di registrare l'output della Console Seriale prima di avviare la procedura per catturare il dump di memoria.

Infine, eliminare tutti i dati non necessari dal file di registro e memorizzare il file come `filename.rom` e utilizzare binwalk per estrarre i contenuti:
```
binwalk -e <filename.rom>
```
Questo elencherà i possibili contenuti dall'EEPROM in base alle firme trovate nel file esadecimale.

Anche se è necessario notare che non è sempre il caso che l'uboot sia sbloccato anche se viene utilizzato. Se il tasto Invio non fa nulla, controllare se ci sono tasti diversi come il tasto Spazio, ecc. Se il bootloader è bloccato e non viene interrotto, questo metodo non funzionerebbe. Per verificare se uboot è il bootloader del dispositivo, controllare l'output sulla Console UART durante l'avvio del dispositivo. Potrebbe menzionare uboot durante l'avvio.

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale di WhiteIntel è combattere le violazioni degli account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusivi [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
