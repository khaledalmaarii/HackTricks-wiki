# UART

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Basiese Inligting

UART is 'n seriële protokol, wat beteken dat dit data tussen komponente een bit op 'n slag oordra. In teenstelling, oordra parallelle kommunikasieprotokolle data gelyktydig deur meervoudige kanale. Gewone seriële protokolle sluit RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express, en USB in.

Gewoonlik word die lyn hoog gehou (op 'n logiese 1-waarde) terwyl UART in die idle-toestand is. Dan, om die begin van 'n data-oordrag aan te dui, stuur die versender 'n beginbit na die ontvanger, tydens watter die sein laag gehou word (op 'n logiese 0-waarde). Vervolgens stuur die versender vyf tot agt databits wat die werklike boodskap bevat, gevolg deur 'n opsionele pariteitsbit en een of twee stopbietjies (met 'n logiese 1-waarde), afhangende van die konfigurasie. Die pariteitsbit, wat vir foutkontrole gebruik word, word selde in die praktyk gesien. Die stopbit (of bietjies) dui die einde van die oordrag aan.

Ons noem die mees algemene konfigurasie 8N1: agt databits, geen pariteit, en een stopbit. Byvoorbeeld, as ons die karakter C, of 0x43 in ASCII, in 'n 8N1 UART-konfigurasie wou stuur, sou ons die volgende bietjies stuur: 0 (die beginbit); 0, 1, 0, 0, 0, 0, 1, 1 (die waarde van 0x43 in binêre vorm), en 0 (die stopbit).

![](<../../.gitbook/assets/image (761).png>)

Hardeware gereedskap om met UART te kommunikeer:

* USB-na-seriële adapter
* Adapters met die CP2102 of PL2303 skyfies
* Veeldoelige gereedskap soos: Bus Pirate, die Adafruit FT232H, die Shikra, of die Attify Badge

### Identifisering van UART-poorte

UART het 4 poorte: **TX**(Stuur), **RX**(Ontvang), **Vcc**(Spanning), en **GND**(Grond). Jy mag dalk 4 poorte met die **`TX`** en **`RX`** letters **geskryf** op die PCB vind. Maar as daar geen aanduiding is nie, mag jy dit dalk self moet probeer vind met 'n **multimeter** of 'n **logika-analiseerder**.

Met 'n **multimeter** en die toestel afgeskakel:

* Om die **GND**-pen te identifiseer, gebruik die **Deurlooptoets**-modus, plaas die agterleier in die grond en toets met die rooi een totdat jy 'n geluid van die multimeter hoor. Verskeie GND-penne kan op die PCB gevind word, sodat jy dalk die een wat aan UART behoort, gevind het of nie.
* Om die **VCC-poort** te identifiseer, stel die **DC-spanningsmodus** in en stel dit op tot 20 V spanning. Swart sonde op grond en rooi sonde op die pen. Skakel die toestel aan. As die multimeter 'n konstante spanning van óf 3.3 V óf 5 V meet, het jy die Vcc-pen gevind. As jy ander spanninge kry, probeer met ander poorte.
* Om die **TX** **poort** te identifiseer, **DC-spanningsmodus** tot 20 V spanning, swart sonde op grond, en rooi sonde op die pen, en skakel die toestel aan. As jy vind dat die spanning vir 'n paar sekondes fluktueer en dan stabiliseer teen die Vcc-waarde, het jy waarskynlik die TX-poort gevind. Dit is omdat dit wanneer dit aangeskakel word, 'n paar foutdata stuur.
* Die **RX-poort** sou die naaste een aan die ander 3 wees, dit het die laagste spanningfluktuerings en die laagste algehele waarde van al die UART-penne.

Jy kan die TX- en RX-poorte verwar en niks sal gebeur nie, maar as jy die GND- en die VCC-poort verwar, kan jy die stroombaan beskadig.

In sommige teikentoestelle is die UART-poort deur die vervaardiger gedeaktiveer deur RX of TX of selfs beide te deaktiveer. In daardie geval kan dit nuttig wees om die verbindinge op die stroombord na te spoor en 'n paar breekpunte te vind. 'n Sterk aanduiding dat daar geen opsporing van UART is nie en die onderbreking van die stroombaan, is om die toestelwaarborg te kontroleer. As die toestel met 'n waarborg gestuur is, laat die vervaardiger 'n paar foutopsporingskoppelvlakke (in hierdie geval, UART) en het dus die UART afgeskakel en sal dit weer aanskakel terwyl dit foutopsporing doen. Hierdie breekpunte kan deur soldering of jumperdrade aangesluit word.

### Identifisering van die UART Baud Tempo

Die maklikste manier om die korrekte baud tempo te identifiseer, is om na die **TX-pen se uitset te kyk en probeer om die data te lees**. As die data wat jy ontvang nie leesbaar is nie, skakel oor na die volgende moontlike baud tempo totdat die data leesbaar word. Jy kan 'n USB-na-seriële adapter of 'n veeldoelige toestel soos Bus Pirate gebruik om dit te doen, gekoppel met 'n hulpprogram, soos [baudrate.py](https://github.com/devttys0/baudrate/). Die mees algemene baud tempos is 9600, 38400, 19200, 57600, en 115200.

{% hint style="danger" %}
Dit is belangrik om in ag te neem dat in hierdie protokol jy die TX van die een toestel aan die RX van die ander moet koppel!
{% endhint %}

## CP210X UART na TTY-Adapter

Die CP210X Skyf word gebruik in baie prototiperingborde soos NodeMCU (met esp8266) vir Seriële Kommunikasie. Hierdie adapters is relatief goedkoop en kan gebruik word om met die UART-koppelvlak van die teiken te verbind. Die toestel het 5-penne: 5V, GND, RXD, TXD, 3.3V. Maak seker om die spanning soos ondersteun deur die teiken te verbind om enige skade te voorkom. Verbind uiteindelik die RXD-pen van die Adapter met die TXD van die teiken en die TXD-pen van die Adapter met die RXD van die teiken.

As die adapter nie opgespoor word nie, maak seker dat die CP210X-bestuurders in die gasstelsel geïnstalleer is. Sodra die adapter opgespoor en gekoppel is, kan gereedskap soos picocom, minicom of skerm gebruik word.

Om die toestelle wat aan Linux/MacOS-stelsels gekoppel is, te lys:
```
ls /dev/
```
Vir basiese interaksie met die UART-koppelvlak, gebruik die volgende bevel:
```
picocom /dev/<adapter> --baud <baudrate>
```
Vir minicom, gebruik die volgende bevel om dit te konfigureer:
```
minicom -s
```
Stel die instellings soos baudkoers en toestelnaam in die `Serial port setup` opsie.

Na konfigurasie, gebruik die bevel `minicom` om die UART-konsole te begin.

## UART Via Arduino UNO R3 (Verwyderbare Atmel 328p Chip Borde)

Indien UART Seriële na USB-omsetters nie beskikbaar is nie, kan 'n Arduino UNO R3 met 'n vinnige hak gebruik word. Aangesien die Arduino UNO R3 gewoonlik oral beskikbaar is, kan dit baie tyd bespaar.

Arduino UNO R3 het 'n USB na Seriële omsetter wat op die bord self ingebou is. Om 'n UART-verbinding te kry, trek net die Atmel 328p mikrokontroller-skyfie uit die bord. Hierdie hak werk op Arduino UNO R3-variante waar die Atmel 328p nie op die bord gesoldeer is nie (SMD-weergawe word daarin gebruik). Verbind die RX-pen van die Arduino (Digitale Pen 0) met die TX-pen van die UART-koppelvlak en die TX-pen van die Arduino (Digitale Pen 1) met die RX-pen van die UART-koppelvlak.

Laastens word dit aanbeveel om die Arduino IDE te gebruik om die Seriële Konsole te kry. In die `tools` afdeling in die kieslys, kies die `Serial Console` opsie en stel die baudkoers in volgens die UART-koppelvlak.

## Bus Pirate

In hierdie scenario gaan ons die UART-kommunikasie van die Arduino wat al die afdrukke van die program na die Seriële Monitor stuur, afluister.
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
## Dumping Firmware met UART-konsole

UART-konsole bied 'n uitstekende manier om met die onderliggende firmware in die uitvoeringsomgewing te werk. Maar wanneer die toegang tot die UART-konsole slegs leesbaar is, kan dit baie beperkings inbring. In baie ingebedde toestelle word die firmware gestoor in EEPROM's en uitgevoer in verwerkers met vlugtige geheue. Daarom word die firmware as leesbaar gehou aangesien die oorspronklike firmware tydens vervaardiging binne die EEPROM self is en enige nuwe lêers sou verlore gaan as gevolg van vlugtige geheue. Daarom is dit waardevol om die firmware te dump terwyl jy met ingebedde firmwares werk.

Daar is baie maniere om dit te doen en die SPI-afdeling dek metodes om die firmware direk uit die EEPROM met verskeie toestelle te onttrek. Alhoewel, dit word aanbeveel om eers te probeer om die firmware te dump met UART aangesien die dump van firmware met fisiese toestelle en eksterne interaksies riskant kan wees.

Die dump van firmware vanaf die UART-konsole vereis dat jy eerste toegang tot die aanvangsladers kry. Baie gewilde verskaffers maak gebruik van <b>uboot</b> (Universal Bootloader) as hul aanvangslader om Linux te laai. Daarom is dit noodsaaklik om toegang tot <b>uboot</b> te kry.

Om toegang tot die <b>boot</b> aanvangslader te kry, verbind die UART-poort met die rekenaar en gebruik enige van die Seriële Konsole-hulpmiddels en hou die kragtoevoer na die toestel afgeskakel. Wanneer die opstelling gereed is, druk die Enter-sleutel in en hou dit vas. Verbind uiteindelik die kragtoevoer met die toestel en laat dit opstart.

Deur dit te doen, sal dit <b>uboot</b> onderbreek om te laai en 'n kieslys voorsien. Dit word aanbeveel om <b>uboot</b> bevele te verstaan en die hulpkieslys te gebruik om hulle te lys. Dit kan die `help` bevel wees. Aangesien verskillende verskaffers verskillende konfigurasies gebruik, is dit noodsaaklik om elkeen van hulle afsonderlik te verstaan.

Gewoonlik is die bevel om die firmware te dump:
```
md
```
wat staan vir "geheue dump". Dit sal die geheue (EEPROM-inhoud) op die skerm dump. Dit word aanbeveel om die Serial Console-uitset te log voordat die prosedure begin word om die geheue dump vas te vang.

Laastens, sny net al die onnodige data uit die log-lêer uit en stoor die lêer as `lêernaam.rom` en gebruik binwalk om die inhoud te onttrek:
```
binwalk -e <filename.rom>
```
Dit sal die moontlike inhoud van die EEPROM lys volgens die handtekeninge wat in die hekslêer gevind is.

Alhoewel dit noodsaaklik is om op te let dat dit nie altyd die geval is dat die <b>uboot</b> oopgemaak is selfs as dit gebruik word nie. As die Enter-sleutel niks doen nie, kyk vir verskillende sleutels soos die Spasiesleutel, ens. As die opstartlader gesluit is en nie onderbreek word nie, sal hierdie metode nie werk nie. Om te kyk of <b>uboot</b> die opstartlader vir die toestel is, kyk na die uitset op die UART-konsole terwyl die toestel opstart. Dit kan <b>uboot</b> noem terwyl dit opstart.

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
