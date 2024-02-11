# FISSURE - Kitengo cha RF

**Uelewa na Uhandisi wa Nyuma kwa Kutumia Ishara za SDR zisizo na Mzunguko**

FISSURE ni mfumo wa chanzo wazi wa RF na uhandisi wa nyuma ulioundwa kwa viwango vyote vya ujuzi na vifungo vya ugunduzi na uainishaji wa ishara, ugunduzi wa itifaki, utekelezaji wa mashambulizi, uchambuzi wa IQ, uchambuzi wa udhaifu, otomatiki, na AI/ML. Mfumo huu ulijengwa ili kuhamasisha ushirikiano wa haraka wa moduli za programu, redio, itifaki, data ya ishara, hati za skrini, michoro ya mzunguko, vifaa vya marejeleo, na zana za watu wengine. FISSURE ni kifaa kinachowezesha mchakato ambao unaweka programu katika eneo moja na kuruhusu timu kujifunza kwa urahisi huku wakishiriki mipangilio sawa ya msingi kwa usambazaji maalum wa Linux.

Mfumo na zana zilizojumuishwa na FISSURE zimeundwa kugundua uwepo wa nishati ya RF, kuelewa sifa za ishara, kukusanya na kuchambua sampuli, kukuza njia za kutuma na/au kuingiza, na kuunda malipo au ujumbe maalum. FISSURE ina maktaba inayoongezeka ya habari za itifaki na ishara ili kusaidia katika utambuzi, uundaji wa pakiti, na kufanya majaribio ya kufanya kosa. Uwezo wa kuhifadhi kwenye mtandao upo ili kupakua faili za ishara na kujenga orodha za kucheza ili kusimuliza trafiki na kujaribu mifumo.

Namna ya kirafiki ya msimbo wa Python na kiolesura cha mtumiaji inaruhusu wanaanza kujifunza haraka juu ya zana maarufu na mbinu zinazohusiana na RF na uhandisi wa nyuma. Waelimishaji katika usalama wa mtandao na uhandisi wanaweza kutumia vifaa vilivyomo au kutumia mfumo huu kuonyesha matumizi yao halisi ya ulimwengu. Watengenezaji na watafiti wanaweza kutumia FISSURE kwa kazi zao za kila siku au kuonyesha suluhisho zao za kukata kwa hadhira kubwa. Kadiri ufahamu na matumizi ya FISSURE yanavyoongezeka katika jamii, ndivyo uwezo wake na upana wa teknolojia inayojumuisha itakavyoongezeka.

**Maelezo Zaidi**

* [AIS Ukurasa](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slaidi](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Karatasi](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Mkataba wa Mazungumzo ya Udukuzi](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Kuanza

**Inayoungwa mkono**

Kuna matawi matatu ndani ya FISSURE ili kufanya urambazaji wa faili kuwa rahisi na kupunguza upungufu wa msimbo. Tawi la Python2\_maint-3.7 lina msingi wa msimbo uliojengwa kwa Python2, PyQt4, na GNU Radio 3.7; tawi la Python3\_maint-3.8 limejengwa kwa Python3, PyQt5, na GNU Radio 3.8; na tawi la Python3\_maint-3.10 limejengwa kwa Python3, PyQt5, na GNU Radio 3.10.

|   Mfumo wa Uendeshaji   |   Tawi la FISSURE   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**Katika Maendeleo (beta)**

Mifumo hii ya uendeshaji bado iko katika hali ya beta. Inaendelezwa na kuna vipengele kadhaa ambavyo havipo. Vitu katika programu ya usanidi vinaweza kuingiliana na programu zilizopo au kushindwa kusakinishwa hadi hali hiyo itakapoondolewa.

|     Mfumo wa Uendeshaji     |    Tawi la FISSURE   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Kumbuka: Zana fulani za programu hazifanyi kazi kwa kila mfumo wa uendeshaji. Angalia [Programu na Migongano](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Hii itasakinisha programu tegemezi za PyQt zinazohitajika kuendesha GUI za usakinishaji ikiwa hazijapatikana.

Kisha, chagua chaguo ambalo linalingana vizuri na mfumo wako wa uendeshaji (linapaswa kugunduliwa moja kwa moja ikiwa mfumo wako wa uendeshaji unalingana na chaguo).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Inapendekezwa kusakinisha FISSURE kwenye mfumo wa uendeshaji safi ili kuepuka migongano iliyopo. Chagua vikasha vyote vilivyopendekezwa (kitufe cha Chaguo-msingi) ili kuepuka makosa wakati wa kutumia zana mbalimbali ndani ya FISSURE. Kutakuwa na maombi mengi wakati wa usakinishaji, kwa kawaida yanayouliza ruhusa iliyoinuliwa na majina ya watumiaji. Ikiwa kipengee kina sehemu ya "Thibitisha" mwishoni, usakinishaji utatekeleza amri inayofuata na kuonyesha kipengee cha kisanduku cha rangi ya kijani au nyekundu kulingana na ikiwa kuna makosa yoyote yanayozalishwa na amri hiyo. Vipengee vilivyochaguliwa bila sehemu ya "Thibitisha" vitabaki nyeusi baada ya usakinishaji.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Matumizi**

Fungua terminal na ingiza:
```
fissure
```
Rejelea menyu ya Msaada wa FISSURE kwa maelezo zaidi kuhusu matumizi.

## Maelezo

**Vipengele**

* Dashibodi
* Kituo Kikuu (HIPRFISR)
* Uthibitishaji wa Ishara ya Lengo (TSI)
* Ugunduzi wa Itifaki (PD)
* Flow Graph & Script Executor (FGE)

![vipengele](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Uwezo**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Mgunduzi wa Ishara**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Udanganyifu wa IQ**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Utafutaji wa Ishara**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Ugunduzi wa Mfano**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Mashambulizi**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Orodha ya Ishara**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galeria ya Picha**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Uundaji wa Pakiti**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Uingizaji wa Scapy**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Kadiria ya CRC**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Kuandika Kumbukumbu**_            |

**Vifaa**

Hapa kuna orodha ya vifaa "vilivyosaidiwa" na viwango tofauti vya ushirikiano:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Vifaa vya 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Madarasa

FISSURE inakuja na mwongozo wenye manufaa kadhaa ili kufahamiana na teknolojia na mbinu tofauti. Wengi wanajumuisha hatua za kutumia zana mbalimbali zilizounganishwa katika FISSURE.

* [Mafunzo1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Mafunzo2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Mafunzo3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Mafunzo4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Mafunzo5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Mafunzo6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Mafunzo7: Aina za Data](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Mafunzo8: Vipande vya GNU Radio vilivyoboreshwa](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Mafunzo9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Mafunzo10: Mitihani ya Redio ya Ham](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Mafunzo11: Zana za Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Ramani ya Barabara

* [ ] Ongeza aina zaidi za vifaa, itifaki za RF, vigezo vya ishara, zana za uchambuzi
* [ ] Saidia mifumo zaidi ya uendeshaji
* [ ] Tengeneza vifaa vya darasa kuhusu FISSURE (Mashambulizi ya RF, Wi-Fi, GNU Radio, PyQt, nk)
* [ ] Unda kifaa cha kurekebisha ishara, kifaa cha kuchuja vipengele, na mtaalamu wa ishara na mbinu za AI/ML zinazoweza kuchaguliwa
* [ ] Tekeleza mifumo ya kudemodisha kwa kuzalisha mfululizo wa biti kutoka kwa ishara zisizojulikana
* [ ] Badilisha sehemu kuu za FISSURE kuwa mpango wa kupeleka sensori jumla

## Kuchangia

Mapendekezo ya kuboresha FISSURE yanahimizwa sana. Acha maoni katika ukurasa wa [Majadiliano](https://github.com/ainfosec/FISSURE/discussions) au kwenye Seva ya Discord ikiwa una mawazo yoyote kuhusu yafuatayo:

* Mapendekezo mapya ya vipengele na mabadiliko ya muundo
* Zana za programu na hatua za ufungaji
* Madarasa mapya au nyenzo zaidi kwa madarasa yaliyopo
* Itifaki za RF za kuvutia
* Vifaa zaidi na aina za SDR kwa ushirikiano
* Skrini za uchambuzi wa IQ kwa kutumia Python
* Marekebisho na uboreshaji wa ufungaji

Mchango wa kuboresha FISSURE ni muhimu katika kuharakisha maendeleo yake. Mchango wowote utakaofanya unathaminiwa sana. Ikiwa unataka kuchangia kupitia maendeleo ya nambari, tafadhali gawanya repo na uunda ombi la kuvuta:

1. Gawa mradi
2. Unda tawi lako la kipengee (`git checkout -b feature/AmazingFeature`)
3. Thibitisha mabadiliko yako (`git commit -m 'Ongeza kipengee kizuri'`)
4. Push kwenye tawi (`git push origin feature/AmazingFeature`)
5. Fungua ombi la kuvuta

Kuunda [Masuala](https://github.com/ainfosec/FISSURE/issues) ili kuvuta tahadhari kwa mende pia ni karibu.

## Kufanya Kazi kwa Pamoja

Wasiliana na Maendeleo ya Biashara ya Assured Information Security, Inc. (AIS) ili kupendekeza na kufanya kazi kwa pamoja kwenye FISSURE - iwe ni kwa kutumia muda kwa kuingiza programu yako, kuwa na watu wenye talanta katika AIS kuendeleza suluhisho kwa changamoto zako za kiufundi, au kuingiza FISSURE katika majukwaa/makala mengine.

## Leseni

GPL-3.0

Kwa maelezo ya leseni, angalia faili ya LICENSE.
## Wasiliana

Jiunge na Seva ya Discord: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Fuata kwenye Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Maendeleo ya Biashara - Assured Information Security, Inc. - bd@ainfosec.com

## Mikopo

Tunatambua na tunashukuru kwa watengenezaji hawa:

[Mikopo](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Shukrani

Shukrani maalum kwa Dk. Samuel Mantravadi na Joseph Reith kwa michango yao kwenye mradi huu.
