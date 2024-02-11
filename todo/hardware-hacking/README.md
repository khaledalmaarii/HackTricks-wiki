<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>


#

# JTAG

JTAG maak dit moontlik om 'n grensskandering uit te voer. Die grensskandering analiseer sekere stroombane, insluitend ingebedde grensskanderingselle en registre vir elke pen.

Die JTAG-standaard definieer **spesifieke opdragte vir die uitvoering van grensskanderings**, insluitend die volgende:

* **BYPASS** maak dit moontlik om 'n spesifieke skyf te toets sonder die oorhoofse van deur ander skywe te gaan.
* **SAMPLE/PRELOAD** neem 'n monster van die data wat die toestel binnekom en verlaat wanneer dit in sy normale funksioneringsmodus is.
* **EXTEST** stel en lees penstatusse.

Dit kan ook ander opdragte ondersteun, soos:

* **IDCODE** om 'n toestel te identifiseer
* **INTEST** vir die interne toetsing van die toestel

Jy mag hierdie instruksies teëkom wanneer jy 'n instrument soos die JTAGulator gebruik.

## Die Toets Toegangspoort

Grensskanderings sluit toetse van die vier-draad **Toets Toegangspoort (TAP)** in, 'n algemene doel poort wat toegang bied tot die JTAG-toetsondersteuningsfunksies wat in 'n komponent ingebou is. TAP gebruik die volgende vyf seine:

* Toetsklok-invoer (**TCK**) Die TCK is die **klok** wat bepaal hoe dikwels die TAP-beheerder 'n enkele aksie sal neem (met ander woorde, spring na die volgende toestand in die toestandmasjien).
* Toetsmodusseleksie (**TMS**) invoer TMS beheer die **eindige toestandmasjien**. Met elke klokpuls kontroleer die JTAG TAP-beheerder van die toestel die spanning op die TMS-pen. As die spanning onder 'n sekere drempel is, word die sein as laag beskou en as 0 geïnterpreteer, terwyl as die spanning bo 'n sekere drempel is, word die sein as hoog beskou en as 1 geïnterpreteer.
* Toetsdata-invoer (**TDI**) TDI is die pen wat **data in die skyf stuur deur die skanderingselle**. Elke vervaardiger is verantwoordelik vir die definisie van die kommunikasieprotokol oor hierdie pen, omdat JTAG dit nie definieer nie.
* Toetsdata-uitset (**TDO**) TDO is die pen wat **data uit die skyf stuur**.
* Toetsherstel (**TRST**) invoer Die opsionele TRST stel die eindige toestandmasjien **in 'n bekende goeie toestand**. As alternatief, as die TMS vir vyf opeenvolgende klokperiodes op 1 gehou word, roep dit 'n herstel op, op dieselfde manier as wat die TRST-pen sou doen, vandaar dat TRST opsioneel is.

Soms sal jy in staat wees om daardie penne gemerk op die PCB te vind. In ander gevalle mag jy dit dalk moet **vind**.

## Identifisering van JTAG-penne

Die vinnigste, maar duurste manier om JTAG-poorte op te spoor, is deur die gebruik van die **JTAGulator**, 'n toestel wat spesifiek vir hierdie doel geskep is (hoewel dit **ook UART-penopstellinge kan opspoor**).

Dit het **24 kanale** waaraan jy die penne van die borde kan koppel. Dit voer dan 'n **BF-aanval** uit van al die moontlike kombinasies deur **IDCODE**- en **BYPASS**-grensskanderingsopdragte te stuur. As dit 'n respons ontvang, wys dit die kanaal wat ooreenstem met elke JTAG-sein.

'n Goedkoper, maar baie stadiger manier om JTAG-penopstellinge te identifiseer, is deur die gebruik van die [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) wat gelaai is op 'n Arduino-verenigbare mikrokontroleerder.

Met behulp van **JTAGenum** sal jy eers die penne van die ondersoekende toestel **definieer** wat jy vir die opname sal gebruik. Jy sal na die penopstellingdiagram van die toestel moet verwys en dan hierdie penne met die toetspunte op jou teikentoestel verbind.

'n **Derde manier** om JTAG-penne te identifiseer, is deur die PCB te **ondersoek** vir een van die penopstellinge. In sommige gevalle kan PCB's gerieflik die **Tag-Connect-interface** bied, wat 'n duidelike aanduiding is dat die bord ook 'n JTAG-konnektor het. Jy kan sien hoe daardie interface lyk by [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Daarbenewens kan die **databladsye van die skyfsets op die PCB** penopstellingdiagramme onthul wat na JTAG-konnekteerders verwys.

# SDW

SWD is 'n ARM-spesifieke protokol wat ontwerp is vir foutopsporing.

Die SWD-interface vereis **twee penne**: 'n tweerigting **SWDIO**-sein, wat die ekwivalent is van JTAG se **TDI- en TDO-penne en 'n klok**, en **SWCLK**, wat die ekwivalent is van **TCK** in JTAG. Baie toestelle ondersteun die **Serial Wire of JTAG Debug Port (SWJ-DP)**, 'n gekombineerde JTAG- en SWD-interface wat jou in staat stel om óf 'n SWD- óf JTAG-sonde aan die teiken te koppel.


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
