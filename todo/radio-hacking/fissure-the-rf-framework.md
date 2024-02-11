# FISSURE - Die RF-raamwerk

**Frekwensie-onafhanklike SDR-gebaseerde Seinbegrip en Omgekeerde Ingenieurswese**

FISSURE is 'n oopbron RF- en omgekeerde ingenieurswese-raamwerk wat ontwerp is vir alle vaardigheidsvlakke met hake vir seinopsporing en klassifikasie, protokolontdekking, aanvaluitvoering, IQ-manipulasie, kwesbaarheidsanalise, outomatisering, en AI/ML. Die raamwerk is gebou om die vinnige integrasie van sagtewaremodules, radio's, protokolle, seindata, skripte, vloeigrafieke, verwysingsmateriaal en hulpmiddels van derde partye te bevorder. FISSURE is 'n werkstroomfasiliteerder wat sagteware op een plek hou en spanne in staat stel om vinnig op te skiet terwyl hulle dieselfde bewese basislynkonfigurasie vir spesifieke Linux-distribusies deel.

Die raamwerk en gereedskap wat saam met FISSURE ingesluit is, is ontwerp om die teenwoordigheid van RF-energie op te spoor, die eienskappe van 'n sein te verstaan, monsters te versamel en te analiseer, oordrag- en/of inspuitingstegnieke te ontwikkel, en aangepaste vragte of boodskappe te skep. FISSURE bevat 'n groeiende biblioteek van protokol- en seininligting om te help met identifikasie, pakketskepping en fuzzing. Aanlynargiefmoontlikhede bestaan om seinlêers af te laai en speellyste te bou om verkeer te simuleer en stelsels te toets.

Die vriendelike Python-kodebasis en gebruikerskoppelvlak stel beginners in staat om vinnig te leer oor gewilde gereedskap en tegnieke wat RF en omgekeerde ingenieurswese betrek. Opvoeders in sibersekuriteit en ingenieurswese kan gebruik maak van die ingeboude materiaal of die raamwerk gebruik om hul eie werklike toepassings te demonstreer. Ontwikkelaars en navorsers kan FISSURE gebruik vir hul daaglikse take of om hul innoverende oplossings aan 'n wyer gehoor bekend te stel. Soos bewustheid en gebruik van FISSURE in die gemeenskap groei, sal die omvang van sy vermoëns en die omvang van die tegnologie wat dit omvat, ook groei.

**Addisionele Inligting**

* [AIS-bladsy](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22-skyfies](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22-artikel](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22-video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat-transkripsie](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Aan die gang

**Ondersteun**

Daar is drie takke binne FISSURE om lêernavigasie makliker te maak en koderedundansie te verminder. Die Python2\_maint-3.7-tak bevat 'n kodebasis wat gebou is rondom Python2, PyQt4 en GNU Radio 3.7; die Python3\_maint-3.8-tak is gebou rondom Python3, PyQt5 en GNU Radio 3.8; en die Python3\_maint-3.10-tak is gebou rondom Python3, PyQt5 en GNU Radio 3.10.

|     Bedryfstelsel     |     FISSURE-tak     |
| :-------------------: | :-----------------: |
|  Ubuntu 18.04 (x64)   | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64)  | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64)  | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64)  | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64)  | Python3\_maint-3.8 |

**In Uitvoering (beta)**

Hierdie bedryfstelsels is steeds in beta-status. Hulle is in ontwikkeling en verskeie funksies word nie ondersteun nie. Items in die installeerder kan in konflik wees met bestaande programme of misluk om te installeer totdat die status verwyder is.

|       Bedryfstelsel       |      FISSURE-tak     |
| :-----------------------: | :------------------: |
| DragonOS Focal (x86\_64)  | Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)     | Python3\_maint-3.10 |

Let op: Sekere sagtewarehulpmiddels werk nie vir elke bedryfstelsel nie. Raadpleeg [Sagteware en Konflikte](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Installasie**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Dit sal die PyQt sagteware-afhanklikhede installeer wat nodig is om die installasie GUI's te lanceer as hulle nie gevind word nie.

Kies daarna die opsie wat die beste by jou bedryfstelsel pas (dit behoort outomaties opgespoor te word as jou bedryfstelsel ooreenstem met 'n opsie).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Dit word aanbeveel om FISSURE op 'n skoon bedryfstelsel te installeer om bestaande konflikte te vermy. Kies al die aanbevole keuseblokkies (Verstek-knoppie) om foute te voorkom terwyl jy die verskillende gereedskap binne FISSURE gebruik. Daar sal verskeie aanvrae gedurende die installasie wees, meestal om verhoogde toestemmings en gebruikersname te vra. As 'n item 'n "Verifieer"-afdeling aan die einde bevat, sal die installeerder die opdrag wat volg uitvoer en die keuseblokkie groen of rooi uitlig, afhangende van of enige foute deur die opdrag geproduseer word. Gekontroleerde items sonder 'n "Verifieer"-afdeling sal swart bly na die installasie.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Gebruik**

Maak 'n terminaal oop en tik in:
```
fissure
```
Raadpleeg die FISSURE Help-menus vir meer besonderhede oor die gebruik daarvan.

## Besonderhede

**Komponente**

* Dashboard
* Sentrale Naaf (HIPRFISR)
* Teiken Sein Identifikasie (TSI)
* Protokol Ontdekking (PD)
* Vloeidiagram & Skrips Uitvoerder (FGE)

![komponente](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Vermoëns**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Sein Detektor**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulasie**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Sein Opsoek**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Patroon Herkenning**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Aanvalle**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Sein Speellyste**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Beeldgalerie**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Pakket Skepping**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integrasie**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Kalkulator**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logboek**_            |

**Hardeware**

Hier is 'n lys van "ondersteunde" hardeware met verskillende vlakke van integrasie:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lesse

FISSURE kom met verskeie nuttige gidse om bekend te raak met verskillende tegnologieë en tegnieke. Baie van hulle bevat stappe vir die gebruik van verskillende gereedskap wat in FISSURE geïntegreer is.

* [Les 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Les 2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Les 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Les 4: ESP Borde](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Les 5: Radiosonde Opvolging](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Les 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Les 7: Data Tipes](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Les 8: Aangepaste GNU Radio Blokke](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Les 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Les 10: Ham Radio Eksamens](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Les 11: Wi-Fi Gereedskap](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Padkaart

* [ ] Voeg meer hardeware tipes, RF protokolle, sein parameters, analise gereedskap by
* [ ] Ondersteun meer bedryfstelsels
* [ ] Ontwikkel klas materiaal rondom FISSURE (RF Aanvalle, Wi-Fi, GNU Radio, PyQt, ens.)
* [ ] Skep 'n sein kondisioneerder, kenmerk-onttrekker, en sein klassifiseerder met selekteerbare AI/ML tegnieke
* [ ] Implementeer herhalende demodulasie meganismes om 'n bitstroom van onbekende seine te produseer
* [ ] Oorgang die hoof FISSURE komponente na 'n generiese sensor node implementering skema

## Bydrae

Voorstelle om FISSURE te verbeter word sterk aangemoedig. Laat 'n kommentaar op die [Besprekings](https://github.com/ainfosec/FISSURE/discussions) bladsy of in die Discord-bediener as jy enige gedagtes het oor die volgende:

* Nuwe funksie voorstelle en ontwerp veranderinge
* Sagteware gereedskap met installasie stappe
* Nuwe lesse of addisionele materiaal vir bestaande lesse
* RF protokolle van belang
* Meer hardeware en SDR tipes vir integrasie
* IQ analise skripte in Python
* Installasie korreksies en verbeteringe

Bydraes om FISSURE te verbeter is van kritieke belang om die ontwikkeling te versnel. Enige bydraes wat jy maak, word baie waardeer. As jy deur kodedevelopement wil bydra, vurk asseblief die repo en skep 'n pull versoek:

1. Vurk die projek
2. Skep jou funksie tak (`git checkout -b feature/AmazingFeature`)
3. Bevestig jou veranderinge (`git commit -m 'Add some AmazingFeature'`)
4. Druk na die tak (`git push origin feature/AmazingFeature`)
5. Maak 'n pull versoek oop

Die skep van [Kwessies](https://github.com/ainfosec/FISSURE/issues) om aandag te vestig op foute word ook verwelkom.

## Samewerking

Kontak Assured Information Security, Inc. (AIS) Besigheidsontwikkeling om enige FISSURE-samewerkingsgeleenthede voor te stel en te formaliseer - of dit nou deur tyd te wy aan die integrasie van jou sagteware, deur die talentvolle mense by AIS oplossings vir jou tegniese uitdagings te laat ontwikkel, of deur FISSURE in ander platforms/toepassings te integreer.

## Lisensie

GPL-3.0

Vir lisensiebesonderhede, sien die LICENSE-lêer.
## Kontak

Sluit aan by die Discord-bediener: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Volg op Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Besigheidsontwikkeling - Assured Information Security, Inc. - bd@ainfosec.com

## Krediete

Ons erken en is dankbaar vir hierdie ontwikkelaars:

[Krediete](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Erkenning

Spesiale dank aan Dr. Samuel Mantravadi en Joseph Reith vir hul bydraes tot hierdie projek.
