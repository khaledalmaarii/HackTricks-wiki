<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


# Informazioni di base

UART è un protocollo seriale, il che significa che trasferisce i dati tra i componenti un bit alla volta. Al contrario, i protocolli di comunicazione parallela trasmettono i dati contemporaneamente attraverso più canali. I protocolli seriali comuni includono RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express e USB.

In generale, la linea viene mantenuta alta (a un valore logico 1) mentre UART è nello stato di inattività. Successivamente, per segnalare l'inizio di un trasferimento di dati, il trasmettitore invia un bit di start al ricevitore, durante il quale il segnale viene mantenuto basso (a un valore logico 0). Successivamente, il trasmettitore invia da cinque a otto bit di dati contenenti il messaggio effettivo, seguiti da un bit di parità opzionale e uno o due bit di stop (con un valore logico 1), a seconda della configurazione. Il bit di parità, utilizzato per il controllo degli errori, è raramente utilizzato nella pratica. Il bit di stop (o i bit) indicano la fine della trasmissione.

Chiamiamo la configurazione più comune 8N1: otto bit di dati, nessuna parità e un bit di stop. Ad esempio, se volessimo inviare il carattere C, o 0x43 in ASCII, in una configurazione UART 8N1, invieremmo i seguenti bit: 0 (il bit di start); 0, 1, 0, 0, 0, 0, 1, 1 (il valore di 0x43 in binario) e 0 (il bit di stop).

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

Strumenti hardware per comunicare con UART:

* Adattatore USB-seriale
* Adattatori con chip CP2102 o PL2303
* Strumento multipurpose come: Bus Pirate, Adafruit FT232H, Shikra o Attify Badge

## Identificazione delle porte UART

UART ha 4 porte: **TX** (trasmetti), **RX** (ricevi), **Vcc** (tensione) e **GND** (terra). Potresti essere in grado di trovare 4 porte con le lettere **`TX`** e **`RX`** **scritte** sulla PCB. Ma se non c'è alcuna indicazione, potresti dover cercare di trovarle tu stesso utilizzando un **multimetro** o un **analizzatore logico**.

Con un **multimetro** e il dispositivo spento:

* Per identificare il pin **GND** utilizza la modalità **Test di continuità**, posiziona il cavo di ritorno a terra e testa con il cavo rosso fino a sentire un suono dal multimetro. Sulla PCB possono essere presenti diversi pin GND, quindi potresti aver trovato o meno quello relativo a UART.
* Per identificare la porta **VCC**, imposta la modalità **tensione DC** e impostala su 20 V di tensione. Sonda nera a terra e sonda rossa sul pin. Accendi il dispositivo. Se il multimetro misura una tensione costante di 3,3 V o 5 V, hai trovato il pin Vcc. Se ottieni altre tensioni, riprova con altre porte.
* Per identificare la porta **TX**, modalità **tensione DC** fino a 20 V di tensione, sonda nera a terra e sonda rossa sul pin, e accendi il dispositivo. Se trovi che la tensione fluttua per alcuni secondi e poi si stabilizza al valore di Vcc, molto probabilmente hai trovato la porta TX. Questo perché quando si accende, invia alcuni dati di debug.
* La porta **RX** sarebbe quella più vicina alle altre 3, ha la fluttuazione di tensione più bassa e il valore complessivo più basso di tutti i pin UART.

Puoi confondere le porte TX e RX e non succederà nulla, ma se confondi la porta GND e la porta VCC potresti danneggiare il circuito.

Con un analizzatore logico:

## Identificazione del baud rate UART

Il modo più semplice per identificare il baud rate corretto è guardare l'output del pin **TX e cercare di leggere i dati**. Se i dati che ricevi non sono leggibili, passa al successivo baud rate possibile fino a quando i dati diventano leggibili. Puoi utilizzare un adattatore USB-seriale o un dispositivo multipurpose come Bus Pirate per fare ciò, abbinato a uno script di supporto, come [baudrate.py](https://github.com/devttys0/baudrate/). I baud rate più comuni sono 9600, 38400, 19200, 57600 e 115200.

{% hint style="danger" %}
È importante notare che in questo protocollo è necessario collegare il TX di un dispositivo al RX dell'altro!
{% endhint %}

# Bus Pirate

In questo scenario stiamo intercettando la comunicazione UART dell'Arduino che sta inviando tutte le stampe del programma al Monitor Seriale.
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
<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
