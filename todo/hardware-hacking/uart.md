<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>


# Osnovne informacije

UART je serijski protokol, što znači da prenosi podatke između komponenti po jednom bitu. Za razliku od toga, paralelni komunikacioni protokoli istovremeno prenose podatke kroz više kanala. Uobičajeni serijski protokoli uključuju RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express i USB.

Općenito, linija se drži visoko (na logičkoj vrednosti 1) dok je UART u stanju mirovanja. Zatim, da bi signalizirao početak prenosa podataka, predajnik šalje startni bit prijemniku, tokom kojeg se signal drži nisko (na logičkoj vrednosti 0). Zatim, predajnik šalje pet do osam podatkovnih bitova koji sadrže stvarnu poruku, praćene opcionim bitom parnosti i jednim ili dva stop bita (sa logičkom vrednošću 1), u zavisnosti od konfiguracije. Bit parnosti, koji se koristi za proveru grešaka, retko se viđa u praksi. Stop bit (ili bitovi) označavaju kraj prenosa.

Najčešća konfiguracija je 8N1: osam podatkovnih bitova, bez parnosti i jedan stop bit. Na primer, ako želimo poslati karakter C, ili 0x43 u ASCII kodu, u UART konfiguraciji 8N1, poslali bismo sledeće bitove: 0 (startni bit); 0, 1, 0, 0, 0, 0, 1, 1 (vrednost 0x43 u binarnom obliku) i 0 (stop bit).

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

Hardverski alati za komunikaciju sa UART-om:

* USB-serial adapter
* Adapteri sa čipovima CP2102 ili PL2303
* Višenamenski alat kao što su Bus Pirate, Adafruit FT232H, Shikra ili Attify Badge

## Identifikacija UART portova

UART ima 4 porta: **TX**(Transmit), **RX**(Receive), **Vcc**(Voltage) i **GND**(Ground). Možda ćete moći da pronađete 4 porta sa slovima **`TX`** i **`RX`** **ispisanim** na PCB-u. Ali ako nema naznake, možda ćete morati da ih sami pronađete koristeći **multimetar** ili **logički analizator**.

Sa **multimetrom** i isključenim uređajem:

* Da biste identifikovali **GND pin** koristite režim **Continuity Test**, postavite zadnji vod u zemlju i testirajte crvenim vodom dok ne čujete zvuk iz multimetra. Na PCB-u se može pronaći nekoliko GND pinova, pa možda pronađete ili ne pronađete onaj koji pripada UART-u.
* Da biste identifikovali **VCC port**, postavite režim **DC voltage** i postavite ga na 20 V napona. Crna sonda na zemlju, a crvena sonda na pin. Uključite uređaj. Ako multimetar meri konstantan napon od 3.3 V ili 5 V, pronašli ste Vcc pin. Ako dobijete druge naponske vrednosti, pokušajte sa drugim portovima.
* Da biste identifikovali **TX port**, postavite režim **DC voltage** na 20 V napona, crna sonda na zemlju, a crvena sonda na pin, i uključite uređaj. Ako primetite da napon fluktuira nekoliko sekundi, a zatim se stabilizuje na vrednosti Vcc, verovatno ste pronašli TX port. To je zato što prilikom uključivanja šalje neke debug podatke.
* **RX port** bi trebao biti najbliži od ostalih 3, ima najmanju fluktuaciju napona i najmanju ukupnu vrednost od svih UART pinova.

Možete pomešati TX i RX portove i ništa se neće desiti, ali ako pomešate GND i VCC port možete uništiti kolo.

Sa logičkim analizatorom:

## Identifikacija UART Baud Rate-a

Najlakši način da identifikujete ispravnu brzinu bauda je da pogledate izlaz sa **TX pina i pokušate pročitati podatke**. Ako primljeni podaci nisu čitljivi, pređite na sledeću moguću brzinu bauda dok podaci ne postanu čitljivi. Možete koristiti USB-serial adapter ili višenamenski uređaj poput Bus Pirate-a za to, uparen sa pomoćnim skriptom, kao što je [baudrate.py](https://github.com/devttys0/baudrate/). Najčešće brzine bauda su 9600, 38400, 19200, 57600 i 115200.

{% hint style="danger" %}
Važno je napomenuti da u ovom protokolu morate povezati TX jednog uređaja sa RX drugog!
{% endhint %}

# Bus Pirate

U ovom scenariju ćemo prisluškivati UART komunikaciju Arduina koji šalje sve ispisane poruke programa na Serial Monitor-u.
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

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
