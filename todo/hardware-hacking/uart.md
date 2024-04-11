# UART

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

UART ni itifaki ya mfululizo, ambayo inamaanisha inahamisha data kati ya vipengele biti moja kwa wakati. Tofauti na itifaki za mawasiliano ya wima hupitisha data kwa wakati mmoja kupitia njia nyingi. Itifaki za mfululizo za kawaida ni pamoja na RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express, na USB.

Kwa ujumla, mstari unashikiliwa juu (kwa thamani ya mantiki 1) wakati UART iko katika hali ya kupumzika. Kisha, kwa kusudi la kuashiria mwanzo wa uhamisho wa data, mtumaji hutoa biti ya kuanza kwa mpokeaji, wakati ambao ishara inashikiliwa chini (kwa thamani ya mantiki 0). Kisha, mtumaji hutoa biti tano hadi nane za data zinazojumuisha ujumbe halisi, ikifuatiwa na biti ya ukaguzi wa makosa na biti moja au mbili za kusimamisha (zenye thamani ya mantiki 1), kulingana na usanidi. Biti ya ukaguzi wa makosa, inayotumiwa kwa ukaguzi wa makosa, mara chache huonekana kwa vitendo. Biti ya kusimamisha (au biti) inaashiria mwisho wa uhamisho.

Tuitie usanidi wa kawaida zaidi 8N1: biti nane za data, hakuna ukaguzi wa makosa, na biti moja ya kusimamisha. Kwa mfano, ikiwa tunataka kutuma herufi C, au 0x43 katika ASCII, katika usanidi wa UART wa 8N1, tungepeleka biti zifuatazo: 0 (biti ya kuanza); 0, 1, 0, 0, 0, 0, 1, 1 (thamani ya 0x43 katika tarakilishi), na 0 (biti ya kusimamisha).

![](<../../.gitbook/assets/image (761).png>)

Vyombo vya vifaa vya mawasiliano na UART:

* Kigeuzi cha USB-kwa-mfululizo
* Vigeuzi vyenye chips za CP2102 au PL2303
* Zana ya aina nyingi kama: Pirate ya Bus, Adafruit FT232H, Shikra, au Bajeti ya Attify

### Kutambua Bandari za UART

UART ina bandari 4: **TX**(Tuma), **RX**(Pokea), **Vcc**(Voltage), na **GND**(Ground). Unaweza kupata bandari 4 zenye herufi za **`TX`** na **`RX`** **zilizoandikwa** kwenye PCB. Lakini ikiwa hakuna ishara, unaweza kuhitaji kujaribu kuzipata mwenyewe kwa kutumia **multimeter** au **analyzer ya mantiki**.

Kwa **multimeter** na kifaa kimezimwa:

* Kutambua pin ya **GND** tumia mode ya **Majaribio ya Uendelezaji**, weka kamba ya nyuma kwenye ardhi na jaribu na ile nyekundu mpaka usikie sauti kutoka kwa multimeter. Pins kadhaa za GND zinaweza kupatikana kwenye PCB, kwa hivyo unaweza kuwa umepata au hujapata ile inayomilikiwa na UART.
* Kutambua **bandari ya VCC**, weka mode ya **volts ya DC** na iweke hadi 20 V ya voltage. Kamba nyeusi kwenye ardhi na kamba nyekundu kwenye pin. Washa kifaa. Ikiwa multimeter inapima voltage ya kudumu ya 3.3 V au 5 V, umepata pin ya Vcc. Ikiwa unapata voltages nyingine, jaribu tena na bandari zingine.
* Kutambua **TX** **bandari**, **mode ya voltage ya DC** hadi 20 V ya voltage, kamba nyeusi kwenye ardhi, na kamba nyekundu kwenye pin, na uweke kifaa. Ikiwa unagundua voltage inabadilika kwa sekunde chache na kisha inadhibitika kwa thamani ya Vcc, labda umepata bandari ya TX. Hii ni kwa sababu wakati wa kuwasha, inatuma data fulani ya uchunguzi.
* **Bandari ya RX** itakuwa ile karibu zaidi na zingine 3, ina mabadiliko madogo ya voltage na thamani ya chini zaidi ya jumla ya pini zote za UART.

Unaweza kuchanganya bandari za TX na RX na hakuna kitakachotokea, lakini ikiwa unachanganya GND na bandari ya VCC unaweza kuharibu mzunguko.

Kwenye vifaa vya lengo fulani, bandari ya UART inaweza kuwa imelemazwa na mtengenezaji kwa kulemaza RX au TX au hata zote mbili. Katika kesi hiyo, inaweza kuwa na manufaa kufuatilia mawasiliano kwenye bodi ya mzunguko na kupata sehemu ya kuvunja. Kiashiria kikali kuhusu kuthibitisha kutokuwepo kwa kugundua UART na kuvunjika kwa mzunguko ni kuangalia dhamana ya kifaa. Ikiwa kifaa kimesafirishwa na dhamana fulani, mtengenezaji huacha vipengele vya uchunguzi (katika kesi hii, UART) na hivyo, lazima awe amekataza UART na ataiunganisha tena wakati wa kutatua hitilafu. Pins hizi za kuvunja zinaweza kuunganishwa kwa kusodolewa au nyaya za jumper.

### Kutambua Kiwango cha Baud ya UART

Njia rahisi ya kutambua kiwango sahihi cha baud ni kuangalia **matokeo ya pin ya TX na kujaribu kusoma data**. Ikiwa data unayopokea haiwezi kusomwa, badilisha kiwango cha baud kinachowezekana hadi data iweze kusomwa. Unaweza kutumia kigeuzi cha USB-kwa-mfululizo au kifaa cha aina nyingi kama Bus Pirate kufanya hivi, pamoja na script msaidizi, kama [baudrate.py](https://github.com/devttys0/baudrate/). Viwango vya baud vya kawaida ni 9600, 38400, 19200, 57600, na 115200.

{% hint style="danger" %}
Ni muhimu kutambua kwamba katika itifaki hii unahitaji kuunganisha TX ya kifaa kimoja na RX ya kingine!
{% endhint %}

## Kigeuzi cha CP210X UART kwenda TTY

Chip ya CP210X hutumiwa kwenye bodi nyingi za prototyping kama NodeMCU (na esp8266) kwa Mawasiliano ya Mfululizo. Vigeuzi hivi ni vya bei nafuu na vinaweza kutumika kuunganisha kwenye kiolesura cha UART cha lengo. Kifaa kina pins 5: 5V, GND, RXD, TXD, 3.3V. Hakikisha kuunganisha voltage kama inavyoungwa mkono na lengo ili kuepuka uharibifu wowote. Hatimaye unganisha pin ya RXD ya Kigeuzi kwa TXD ya lengo na pin ya TXD ya Kigeuzi kwa RXD ya lengo.

Ikiwa kigeuzi hakigunduliwi, hakikisha madereva ya CP210X yamefungwa kwenye mfumo wa mwenyeji. Mara tu kigeuzi kinapogunduliwa na kuunganishwa, zana kama picocom, minicom au screen zinaweza kutumika.

Kutaja vifaa vilivyounganishwa kwenye mifumo ya Linux/MacOS:
```
ls /dev/
```
Kwa mwingiliano wa msingi na kiolesura cha UART, tumia amri ifuatayo:
```
picocom /dev/<adapter> --baud <baudrate>
```
Kwa minicom, tumia amri ifuatayo kuiboresha:
```
minicom -s
```
Configure mazingira kama baudrate na jina la kifaa katika chaguo la `Serial port setup`.

Baada ya usanidi, tumia amri `minicom` kuanza kupata Konsoli ya UART.

## UART Kupitia Arduino UNO R3 (Makaratasi ya Chip ya Atmel 328p yanayoweza kuondolewa)

Ikiwa viunganishi vya UART Serial hadi USB havipatikani, Arduino UNO R3 inaweza kutumika na udukuzi wa haraka. Kwa kuwa Arduino UNO R3 kawaida inapatikana mahali popote, hii inaweza kuokoa muda mwingi.

Arduino UNO R3 ina adapta ya USB hadi Serial iliyojengwa kwenye bodi yenyewe. Ili kupata uunganisho wa UART, tuvute nje chipu ya mikrokontrola ya Atmel 328p kutoka kwenye bodi. Udukuzi huu unafanya kazi kwenye toleo la Arduino UNO R3 lenye Atmel 328p ambayo haijasuluhishwa kwenye bodi (toleo la SMD linatumika ndani yake). Unganisha pin ya RX ya Arduino (Pin ya Dijitali 0) kwenye pin ya TX ya Kiolesura cha UART na pin ya TX ya Arduino (Pin ya Dijitali 1) kwenye pin ya RX ya kiolesura cha UART.

Hatimaye, inapendekezwa kutumia Arduino IDE kupata Konsoli ya Serial. Katika sehemu ya `zana` kwenye menyu, chagua chaguo la `Konsoli ya Serial` na weka kiwango cha baud kulingana na kiolesura cha UART.

## Bus Pirate

Katika hali hii, tunakusudia kunasa mawasiliano ya UART ya Arduino ambayo inatuma maandishi yote ya programu kwa Mfuatiliaji wa Serial.
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
## Kudondosha Firmware na Konsoli ya UART

Konsoli ya UART hutoa njia nzuri ya kufanya kazi na firmware ya msingi katika mazingira ya runtime. Lakini wakati ufikiaji wa Konsoli ya UART ni wa kusoma tu, inaweza kuleta vizuizi vingi. Katika vifaa vingi vilivyowekwa, firmware hufungwa katika EEPROMs na kutekelezwa kwenye processors zenye kumbukumbu ya muda. Hivyo, firmware inabaki kuwa ya kusoma tu tangu firmware ya awali wakati wa utengenezaji iko ndani ya EEPROM yenyewe na faili mpya zingepotea kutokana na kumbukumbu ya muda. Hivyo, kudondosha firmware ni juhudi muhimu wakati wa kufanya kazi na firmware zilizowekwa.

Kuna njia nyingi za kufanya hivi na sehemu ya SPI inashughulikia njia za kutoa firmware moja kwa moja kutoka kwenye EEPROM na vifaa mbalimbali. Ingawa, inapendekezwa kujaribu kwanza kudondosha firmware na UART kwani kudondosha firmware na vifaa vya kimwili na mwingiliano wa nje kunaweza kuwa hatari.

Kudondosha firmware kutoka kwenye Konsoli ya UART kunahitaji kupata ufikiaji wa bootloaders kwanza. Wauzaji maarufu wengi hutumia <b>uboot</b> (Universal Bootloader) kama bootloader yao ya kupakia Linux. Hivyo, kupata ufikiaji wa <b>uboot</b> ni lazima.

Ili kupata ufikiaji wa bootloader ya <b>boot</b>, unganisha bandari ya UART kwenye kompyuta na tumia mojawapo ya zana za Konsoli ya Serial na weka ugavi wa umeme kwa kifaa ukiwa umekatwa. Mara tu usanidi uko tayari, bonyeza Kitufe cha Kuingia na kishike. Hatimaye, unganisha ugavi wa umeme kwa kifaa na ruhusu ianze.

Kufanya hivi kutavuruga <b>uboot</b> kutoka kupakia na kutoa menyu. Inapendekezwa kuelewa amri za <b>uboot</b> na kutumia menyu ya msaada kuorodhesha. Hii inaweza kuwa amri ya `help`. Kwa kuwa wauzaji tofauti hutumia mipangilio tofauti, ni muhimu kuelewa kila moja yao kivyake.

Kawaida, amri ya kudondosha firmware ni:
```
md
```
Ambayo inasimama kwa "dumpu ya kumbukumbu". Hii itadumpu kumbukumbu (Maudhui ya EEPROM) kwenye skrini. Inapendekezwa kurekodi pato la Konzi ya Serial kabla ya kuanza mchakato ili kukamata dumpu ya kumbukumbu.

Hatimaye, tuondoe data yote isiyohitajika kutoka kwenye faili la logi na uhifadhi faili kama `jina la faili.rom` na tumie binwalk kuchambua maudhui:
```
binwalk -e <filename.rom>
```
Hii itaorodhesha maudhui yanayowezekana kutoka kwenye EEPROM kulingana na saini zilizopatikana kwenye faili ya hex.

Ingawa, ni muhimu kuzingatia kwamba sio kila wakati <b>uboot</b> iko wazi hata ikiwa inatumika. Ikiwa Kitufe cha Kuingia hakifanyi chochote, angalia vitufe tofauti kama vile Kitufe cha Nafasi, n.k. Ikiwa bootloader imefungwa na haikatishwi, njia hii haitafanya kazi. Ili kujua kama <b>uboot</b> ndio bootloader wa kifaa, angalia matokeo kwenye Konsoli ya UART wakati wa kuanza kifaa. Inaweza kutaja <b>uboot</b> wakati wa kuanza.

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
