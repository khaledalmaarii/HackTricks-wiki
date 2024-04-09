# Hardeware Hak

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## JTAG

JTAG maak dit moontlik om 'n grensskandering uit te voer. Die grensskandering analiseer sekere stroombane, insluitend ingeslote grensskanderingselle en register vir elke pen.

Die JTAG-standaard definieer **spesifieke bevele vir die uitvoering van grensskanderings**, insluitend die volgende:

* **BYPASS** maak dit moontlik om 'n spesifieke skyf te toets sonder die oorhoofse koste van deur ander skywe te gaan.
* **SAMPLE/PRELOAD** neem 'n monster van die data wat die toestel binnekom en verlaat wanneer dit in sy normale funksioneringsmodus is.
* **EXTEST** stel en lees penstatusse.

Dit kan ook ander bevele ondersteun soos:

* **IDCODE** om 'n toestel te identifiseer
* **INTEST** vir die interne toetsing van die toestel

Jy mag hierdie instruksies teëkom wanneer jy 'n instrument soos die JTAGulator gebruik.

### Die Toets Toegangspoort

Grensskanderings sluit toetse van die vier-draad **Toets Toegangspoort (TAP)** in, 'n algemene doel-poort wat toegang bied tot die JTAG-toets-ondersteuningsfunksies wat in 'n komponent ingebou is. TAP gebruik die volgende vyf seine:

* Toetsklok invoer (**TCK**) Die TCK is die **klok** wat bepaal hoe dikwels die TAP-beheerder 'n enkele aksie sal neem (met ander woorde, spring na die volgende toestand in die toestandmasjien).
* Toetsmodus kies (**TMS**) invoer TMS beheer die **eindige toestandmasjien**. Met elke klop van die klok, kontroleer die toestel se JTAG TAP-beheerder die spanning op die TMS-pen. As die spanning onder 'n sekere drempel is, word die sein as laag beskou en as 0 geïnterpreteer, terwyl as die spanning bo 'n sekere drempel is, word die sein as hoog beskou en as 1 geïnterpreteer.
* Toetsdata invoer (**TDI**) TDI is die pen wat **data in die skyf deur die skanderingselle stuur**. Elke vervaardiger is verantwoordelik vir die definisie van die kommunikasieprotokol oor hierdie pen, omdat JTAG dit nie definieer nie.
* Toetsdata uitvoer (**TDO**) TDO is die pen wat **data uit die skyf stuur**.
* Toets herstel (**TRST**) invoer Die opsionele TRST stel die eindige toestandmasjien **na 'n bekende goeie toestand** terug. Alternatiewelik, as die TMS vir vyf opeenvolgende klok-siklusse op 1 gehou word, roep dit 'n herstel op, dieselfde manier as die TRST-pen sou, wat is waarom TRST opsioneel is.

Soms sal jy daardie penne gemerk vind op die PCB. In ander gevalle mag jy dit dalk nodig hê om hulle te **vind**.

### Identifisering van JTAG-penne

Die vinnigste maar duurste manier om JTAG-poorte op te spoor, is deur die **JTAGulator** te gebruik, 'n toestel wat spesifiek vir hierdie doel geskep is (alhoewel dit **ook UART-pinouts kan opspoor**).

Dit het **24 kanale** waaraan jy die bord se penne kan koppel. Dit voer dan 'n **BF-aanval** van al die moontlike kombinasies uit deur **IDCODE** en **BYPASS** grensskanderingsbevele te stuur. As dit 'n reaksie ontvang, wys dit die kanaal wat ooreenstem met elke JTAG-sein.

'n Goedkoper maar baie stadiger manier om JTAG-pinouts te identifiseer, is deur die [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) op 'n Arduino-kompatibele mikrokontroleerder te laai.

Met **JTAGenum** sou jy eers die pinne van die ondersoekende toestel definieer wat jy vir die opnoemings sal gebruik. Jy sou na die toestel se pinout-diagram moet verwys, en dan hierdie pinne met die toetspunte op jou teikentoestel moet verbind.

'n **Derde manier** om JTAG-pinne te identifiseer, is deur die PCB te **ondersoek** vir een van die pinouts. In sommige gevalle mag PCB's gerieflik die **Tag-Connect-interface** voorsien, wat 'n duidelike aanduiding is dat die bord ook 'n JTAG-konnektor het. Jy kan sien hoe daardie interface lyk by [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Daarbenewens kan die **databladsye van die chipset op die PCB** pinout-diagramme onthul wat na JTAG-interfakse verwys.

## SDW

SWD is 'n ARM-spesifieke protokol wat ontwerp is vir foutopsporing.

Die SWD-interface vereis **twee pinne**: 'n tweerigting **SWDIO**-sein, wat die ekwivalent is van JTAG se **TDI en TDO-pinne en 'n klok**, en **SWCLK**, wat die ekwivalent is van **TCK** in JTAG. Baie toestelle ondersteun die **Serial Wire of JTAG Debug Port (SWJ-DP)**, 'n gekombineerde JTAG- en SWD-interface wat jou in staat stel om óf 'n SWD- óf JTAG-sonde aan die teiken te koppel.

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
