<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>


# Basiese Inligting

UART is 'n seriële protokol, wat beteken dat dit data tussen komponente een bit op 'n slag oordra. In teenstelling hiermee oordra parallelle kommunikasieprotokolle data gelyktydig deur meerdere kanale. Gewilde seriële protokolle sluit RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express en USB in.

Gewoonlik word die lyn hoog gehou (met 'n logiese 1-waarde) terwyl UART in die idle-toestand is. Dan, om die begin van 'n data-oordrag aan te dui, stuur die oordrager 'n beginbit na die ontvanger, gedurende wanneer die sein laag gehou word (met 'n logiese 0-waarde). Vervolgens stuur die oordrager vyf tot agt databitte wat die werklike boodskap bevat, gevolg deur 'n opsionele pariteitsbit en een of twee stopbietjies (met 'n logiese 1-waarde), afhangende van die konfigurasie. Die pariteitsbit, wat gebruik word vir foutkontrole, word selde in die praktyk gesien. Die stopbit (of -bietjies) dui die einde van die oordrag aan.

Ons noem die mees algemene konfigurasie 8N1: agt databitte, geen pariteit en een stopbit. Byvoorbeeld, as ons die karakter C, of 0x43 in ASCII, in 'n 8N1 UART-konfigurasie wil stuur, sal ons die volgende bitte stuur: 0 (die beginbit); 0, 1, 0, 0, 0, 0, 1, 1 (die waarde van 0x43 in binêre vorm), en 0 (die stopbit).

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

Hardeware-instrumente om met UART te kommunikeer:

* USB-na-seriële-omsetter
* Adapters met die CP2102- of PL2303-skyfies
* Veeldoelige instrument soos: Bus Pirate, die Adafruit FT232H, die Shikra of die Attify Badge

## Identifisering van UART-poorte

UART het 4 poorte: **TX** (Oordra), **RX** (Ontvang), **Vcc** (Spanning) en **GND** (Grond). Jy mag dalk 4 poorte met die letters **`TX`** en **`RX`** **geskryf** op die PCB vind. Maar as daar geen aanduiding is nie, moet jy dalk probeer om dit self te vind deur 'n **multimeter** of 'n **logiese analiseerder** te gebruik.

Met 'n **multimeter** en die toestel afgeskakel:

* Om die **GND**-pen te identifiseer, gebruik die **Continuïteitstoets**-modus, plaas die agterste leiding in die grond en toets met die rooi een totdat jy 'n geluid van die multimeter hoor. Verskeie GND-penne kan op die PCB gevind word, so jy het dalk die een wat aan UART behoort, gevind of nie.
* Om die **VCC-poort** te identifiseer, stel die **DC-spanningsmodus** in en stel dit op tot 20 V spanning. Swart sonde op grond en rooi sonde op die pen. Skakel die toestel aan. As die multimeter 'n konstante spanning van 3.3 V of 5 V meet, het jy die Vcc-pen gevind. As jy ander spanninge kry, probeer met ander poorte.
* Om die **TX**-poort te identifiseer, **DC-spanningsmodus** tot 20 V spanning, swart sonde op grond en rooi sonde op die pen, en skakel die toestel aan. As jy vind dat die spanning vir 'n paar sekondes wissel en dan stabiliseer teen die Vcc-waarde, het jy waarskynlik die TX-poort gevind. Dit is omdat dit wanneer dit aangeskakel word, sommige foutopsporingsdata stuur.
* Die **RX-poort** sou die naaste een aan die ander 3 wees, dit het die laagste spanningwisseling en die laagste algehele waarde van al die UART-penne.

Jy kan die TX- en RX-poorte verwar en niks sal gebeur nie, maar as jy die GND- en VCC-poort verwar, kan jy die stroombaan beskadig.

Met 'n logiese analiseerder:

## Identifisering van die UART-snelheid

Die maklikste manier om die korrekte baudtempo te identifiseer, is om na die uitset van die **TX-pen te kyk en probeer om die data te lees**. As die data wat jy ontvang nie leesbaar is nie, skakel oor na die volgende moontlike baudtempo totdat die data leesbaar word. Jy kan 'n USB-na-seriële-omsetter of 'n veeldoelige toestel soos Bus Pirate gebruik om dit te doen, saam met 'n hulpskripsie, soos [baudrate.py](https://github.com/devttys0/baudrate/). Die mees algemene baudtempo's is 9600, 38400, 19200, 57600 en 115200.

{% hint style="danger" %}
Dit is belangrik om daarop te let dat jy in hierdie protokol die TX van die een toestel moet verbind met die RX van die ander!
{% endhint %}

# Bus Pirate

In hierdie scenario gaan ons die UART-kommunikasie van die Arduino afluister wat al die afdrukke van die program na die Serial Monitor stuur.
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

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
