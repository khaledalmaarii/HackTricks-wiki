# SPI

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

SPI (Serial Peripheral Interface) ni Itifaki ya Mawasiliano ya Serial ya Synchronous inayotumiwa katika mifumo iliyowekwa kwa mawasiliano ya umbali mfupi kati ya ICs (Integrated Circuits). Itifaki ya Mawasiliano ya SPI hutumia usanifu wa bwana-mtumwa ambao unasimamiwa na Ishara ya Saa na Kuchagua Chip. Usanifu wa bwana-mtumwa unajumuisha bwana (kawaida ni mchakato wa mikro) ambao anasimamia vifaa vya nje kama EEPROM, sensori, vifaa vya kudhibiti, n.k. ambavyo huchukuliwa kuwa watumwa.

Watumwa wengi wanaweza kuunganishwa kwa bwana lakini watumwa hawawezi kuzungumza na wao wenyewe. Watumwa wanatunzwa na pins mbili, saa na kuchagua chip. Kwa kuwa SPI ni itifaki ya mawasiliano ya synchronous, pins za kuingiza na kutoa zifuata ishara za saa. Kuchagua chip hutumiwa na bwana kuchagua mtumwa na kuingiliana naye. Wakati kuchagua chip iko juu, kifaa cha mtumwa hakijachaguliwa wakati inapokuwa chini, chip imechaguliwa na bwana atakuwa anaingiliana na mtumwa.

MOSI (Bwana Nje, Mtumwa Ndani) na MISO (Bwana Ndani, Mtumwa Nje) wanahusika na kutuma na kupokea data. Data hutumwa kwa kifaa cha mtumwa kupitia pin ya MOSI wakati kuchagua chip inashikiliwa chini. Data ya kuingiza ina maagizo, anwani za kumbukumbu au data kulingana na karatasi ya data ya muuzaji wa kifaa cha mtumwa. Baada ya kuingiza sahihi, pin ya MISO inahusika na kutuma data kwa bwana. Data ya kutoa hutumwa moja kwa moja kwenye mzunguko wa saa baada ya kuingia kuisha. Pins za MISO hutoa data hadi data itakapokuwa imehamishwa kabisa au bwana ataweka pin ya kuchagua chip juu (katika kesi hiyo, mtumwa atakoma kutuma na bwana hataisikiliza baada ya mzunguko huo wa saa).

## Kupakua Firmware kutoka kwa EEPROMs

Kupakua firmware inaweza kuwa na manufaa kwa kuchambua firmware na kupata mapungufu ndani yake. Mara nyingi, firmware haipatikani kwenye mtandao au sio muhimu kutokana na mabadiliko ya mambo kama nambari ya mfano, toleo, n.k. Hivyo, kutoa firmware moja kwa moja kutoka kifaa halisi kinaweza kuwa na manufaa kuwa maalum wakati wa kutafuta vitisho.

Kupata Konsoli ya Serial inaweza kuwa na manufaa, lakini mara nyingi hutokea kwamba faili ni za kusoma tu. Hii inazuia uchambuzi kutokana na sababu mbalimbali. Kwa mfano, zana zinazohitajika kutuma na kupokea pakiti hazitakuwepo kwenye firmware. Hivyo, kutoa binaries kwa kuzibadilisha inakuwa sio rahisi. Hivyo, kuwa na firmware nzima iliyopakuliwa kwenye mfumo na kutoa binaries kwa uchambuzi inaweza kuwa na manufaa sana.

Pia, wakati wa kufanya udukuzi na kupata ufikivu wa kimwili kwa vifaa, kupakua firmware kunaweza kusaidia katika kubadilisha faili au kuingiza faili zenye nia mbaya na kisha kuzirekebisha kwenye kumbukumbu ambayo inaweza kuwa na manufaa kwa kuingiza mlango wa nyuma kwenye kifaa. Hivyo, kuna uwezekano mwingi unaweza kufunguliwa na kupakua firmware.

### CH341A Mprogramu na Msomaji wa EEPROM

Kifaa hiki ni zana isiyo ghali kwa ajili ya kupakua firmware kutoka kwa EEPROMs na pia kuzirekebisha na faili za firmware. Hii imekuwa chaguo maarufu kwa kufanya kazi na chips za BIOS za kompyuta (ambazo ni EEPROMs tu). Kifaa hiki kinahusisha kupitia USB na inahitaji zana chache kuanza. Pia, kawaida hufanya kazi haraka, hivyo inaweza kuwa na manufaa katika ufikivu wa kifaa cha kimwili pia.

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

unganisha kumbukumbu ya EEPROM na Mprogramu ya CH341a na unganisha kifaa kwenye kompyuta. Ikiwa kifaa hakigunduliwi, jaribu kufunga madereva kwenye kompyuta. Pia, hakikisha kwamba EEPROM imeunganishwa kwa mwelekeo sahihi (kawaida, weka Pin ya VCC kwa mwelekeo wa nyuma kwa kifaa cha USB) vinginevyo, programu haitaweza kugundua chip. Angalia mchoro ikihitajika:

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

Hatimaye, tumia programu kama flashrom, G-Flash (GUI), n.k. kwa kupakua firmware. G-Flash ni zana ya GUI ya minimal inayofanya kazi haraka na kugundua EEPROM moja kwa moja. Hii inaweza kuwa na manufaa ikiwa firmware inahitaji kuchimbuliwa haraka, bila kuhangaika sana na nyaraka.

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

Baada ya kupakua firmware, uchambuzi unaweza kufanywa kwenye faili za binary. Zana kama strings, hexdump, xxd, binwalk, n.k. zinaweza kutumika kutoa habari nyingi kuhusu firmware pamoja na mfumo mzima wa faili pia.

Kuondoa maudhui kutoka kwa firmware, binwalk inaweza kutumika. Binwalk huchambua kwa saini za hex na kutambua faili kwenye faili ya binary na inaweza kuzitoa.
```
binwalk -e <filename>
```
Faili inaweza kuwa .bin au .rom kulingana na zana na mipangilio iliyotumika.

{% hint style="danger" %}
Tafadhali kumbuka kuwa uchimbaji wa firmware ni mchakato wa kugusa na unahitaji subira nyingi. Kukosea kunaweza kuharibu firmware au hata kufuta kabisa na kufanya kifaa kisitumike kabisa. Inashauriwa kusoma kifaa maalum kabla ya kujaribu kuchimba firmware.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Tafadhali kumbuka kuwa hata kama PINOUT ya Pirate Bus inaonyesha pins kwa **MOSI** na **MISO** kuunganisha na SPI, baadhi ya SPI inaweza kuonyesha pins kama DI na DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

Katika Windows au Linux unaweza kutumia programu [**`flashrom`**](https://www.flashrom.org/Flashrom) kudumpisha maudhui ya kumbukumbu ya flash ikikimbia kitu kama:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
