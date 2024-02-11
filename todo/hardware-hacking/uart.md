<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# Taarifa Msingi

UART ni itifaki ya mfululizo, ambayo inamaanisha kuwa inahamisha data kati ya sehemu moja hadi nyingine biti moja kwa wakati. Kwa tofauti, itifaki za mawasiliano ya mara kwa mara hutoa data kwa wakati mmoja kupitia njia nyingi. Itifaki za mfululizo za kawaida ni pamoja na RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express, na USB.

Kwa ujumla, mstari unashikiliwa juu (kwa thamani ya mantiki 1) wakati UART iko katika hali ya kupumzika. Kisha, ili kuashiria mwanzo wa uhamisho wa data, mtumaji hutoa biti ya mwanzo kwa mpokeaji, wakati ambao ishara inashikiliwa chini (kwa thamani ya mantiki 0). Kisha, mtumaji hutoa biti tano hadi nane za data zinazohusisha ujumbe halisi, ikifuatiwa na biti ya ukaguzi wa kosa ya hiari na biti moja au mbili za kusimamisha (zenye thamani ya mantiki 1), kulingana na usanidi. Biti ya ukaguzi wa kosa, ambayo hutumiwa kwa ukaguzi wa kosa, mara chache huonekana katika vitendo. Biti ya kusimamisha (au biti) inaashiria mwisho wa uhamisho.

Tunaita usanidi wa kawaida zaidi 8N1: biti nane za data, hakuna ukaguzi wa kosa, na biti moja ya kusimamisha. Kwa mfano, ikiwa tunataka kutuma herufi C, au 0x43 katika ASCII, katika usanidi wa UART wa 8N1, tungepeleka biti zifuatazo: 0 (biti ya mwanzo); 0, 1, 0, 0, 0, 0, 1, 1 (thamani ya 0x43 katika namba mbili), na 0 (biti ya kusimamisha).

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

Vifaa vya vifaa vya kuwasiliana na UART:

* Kigeuzi cha USB-kuwa-mfululizo
* Vigeuzi na vijidudu vya CP2102 au PL2303
* Zana ya kusudi mbalimbali kama: Bus Pirate, Adafruit FT232H, Shikra, au Attify Badge

## Kutambua Bandari za UART

UART ina bandari 4: **TX** (Tuma), **RX** (Pokea), **Vcc** (Voltage), na **GND** (Ground). Huenda ukaweza kupata bandari 4 na herufi za **`TX`** na **`RX`** **zilizoandikwa** kwenye PCB. Lakini ikiwa hakuna dalili, huenda ukahitaji kujaribu kuzipata mwenyewe kwa kutumia **multimeter** au **logic analyzer**.

Kwa kutumia **multimeter** na kifaa kimezimwa:

* Ili kutambua pin ya **GND** tumia mode ya **Continuity Test**, weka kichwa cha nyuma kwenye ardhi na jaribu na kichwa chekundu mpaka usikie sauti kutoka kwenye multimeter. Pins kadhaa za GND zinaweza kupatikana kwenye PCB, kwa hivyo unaweza kuwa umepata au hujapata ile inayomiliki UART.
* Ili kutambua bandari ya **VCC**, weka mode ya **DC voltage** na uisete hadi 20 V ya voltage. Chomeka kichwa cheusi kwenye ardhi na kichwa chekundu kwenye pin. Washa kifaa. Ikiwa multimeter inapima voltage thabiti ya 3.3 V au 5 V, umepata pin ya Vcc. Ikiwa unapata voltages nyingine, jaribu na bandari nyingine.
* Ili kutambua bandari ya **TX**, weka mode ya **DC voltage** hadi 20 V ya voltage, chomeka kichwa cheusi kwenye ardhi, na kichwa chekundu kwenye pin, na washa kifaa. Ikiwa unapata voltage inayobadilika kwa sekunde chache na kisha inaendelea kuwa thamani ya Vcc, huenda umepata bandari ya TX. Hii ni kwa sababu wakati wa kuwasha, inatuma data ya kurekebisha baadhi ya matatizo.
* Bandari ya **RX** itakuwa ile iliyo karibu zaidi na nyingine 3, ina mabadiliko ya voltage ya chini zaidi na thamani ya chini zaidi ya jumla ya pini zote za UART.

Unaweza kuchanganya bandari za TX na RX na hakuna kitakachotokea, lakini ikiwa unachanganya bandari za GND na VCC unaweza kuharibu mzunguko.

Kwa kutumia logic analyzer:

## Kutambua Kiwango cha Baud cha UART

Njia rahisi ya kutambua kiwango sahihi cha baud ni kutazama **pato la pin ya TX na kujaribu kusoma data**. Ikiwa data unayopokea haiwezi kusomwa, badilisha kiwango cha baud kinachowezekana kinachofuata hadi data iweze kusomwa. Unaweza kutumia kigeuzi cha USB-kuwa-mfululizo au kifaa cha kusudi mbalimbali kama Bus Pirate kufanya hivi, pamoja na script ya msaidizi, kama [baudrate.py](https://github.com/devttys0/baudrate/). Viwango vya baud vya kawaida ni 9600, 38400, 19200, 57600, na 115200.

{% hint style="danger" %}
Ni muhimu kuzingatia kuwa katika itifaki hii unahitaji kuunganisha TX ya kifaa kimoja na RX ya kifaa kingine!
{% endhint %}

# Bus Pirate

Katika hali hii, tutachunguza mawasiliano ya UART ya Arduino ambayo inatuma uchapishaji wote wa programu kwenye Serial Monitor.
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

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
