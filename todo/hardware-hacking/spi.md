# SPI

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

SPI (Serial Peripheral Interface) ni Protokali ya Mawasiliano ya Mfululizo wa Sawa inayotumika katika mifumo iliyojumuishwa kwa mawasiliano ya umbali mfupi kati ya ICs (Mizunguko Iliyounganishwa). Protokali ya Mawasiliano ya SPI inatumia usanifu wa bwana-mtumwa ambao unaratibiwa na Saa na Ishara ya Kuchagua Chip. Usanifu wa bwana-mtumwa unajumuisha bwana (kawaida ni microprocessor) anayesimamia vifaa vya nje kama EEPROM, sensorer, vifaa vya kudhibiti, n.k. ambavyo vinachukuliwa kuwa watumwa.

Watumwa wengi wanaweza kuunganishwa na bwana lakini watumwa hawawezi kuwasiliana na kila mmoja. Watumwa wanadhibitiwa na pini mbili, saa na kuchagua chip. Kwa kuwa SPI ni protokali ya mawasiliano ya sawa, pini za ingizo na pato zinafuata ishara za saa. Kuchagua chip kunatumika na bwana kuchagua mtumwa na kuwasiliana naye. Wakati kuchagua chip kuna juu, kifaa cha mtumwa hakichaguliwi wakati ambapo ikiwa chini, chip imechaguliwa na bwana atakuwa akifanya kazi na mtumwa.

MOSI (Master Out, Slave In) na MISO (Master In, Slave Out) wanawajibika kwa kutuma data na kupokea data. Data inatumwa kwa kifaa cha mtumwa kupitia pini ya MOSI wakati kuchagua chip inashikiliwa chini. Data ya ingizo ina maagizo, anwani za kumbukumbu au data kulingana na karatasi ya data ya muuzaji wa kifaa cha mtumwa. Kwa ingizo halali, pini ya MISO inawajibika kwa kutuma data kwa bwana. Data ya pato inatumwa hasa katika mzunguko wa saa unaofuata baada ya ingizo kumalizika. Pini za MISO hutuma data hadi data itakapokuwa imetumwa kikamilifu au bwana kuweka pini ya kuchagua chip juu (katika kesi hiyo, mtumwa atasitisha kutuma na bwana hatasikiliza baada ya mzunguko huo wa saa).

## Dumping Firmware from EEPROMs

Kutoa firmware kunaweza kuwa na manufaa kwa kuchambua firmware na kutafuta udhaifu ndani yake. Mara nyingi, firmware haipatikani mtandaoni au haifai kutokana na tofauti za mambo kama vile nambari ya mfano, toleo, n.k. Hivyo, kutoa firmware moja kwa moja kutoka kwa kifaa halisi kunaweza kusaidia kuwa maalum wakati wa kutafuta vitisho.

Kupata Serial Console kunaweza kuwa na manufaa, lakini mara nyingi inatokea kwamba faili ni za kusoma tu. Hii inakandamiza uchambuzi kutokana na sababu mbalimbali. Kwa mfano, zana zinazohitajika kutuma na kupokea pakiti hazitakuwepo katika firmware. Hivyo, kutoa binaries ili kuziunda upya si rahisi. Hivyo, kuwa na firmware yote iliyotolewa kwenye mfumo na kutoa binaries kwa uchambuzi kunaweza kuwa na manufaa sana.

Pia, wakati wa red teaming na kupata ufikiaji wa kimwili kwa vifaa, kutoa firmware kunaweza kusaidia katika kubadilisha faili au kuingiza faili zenye madhara na kisha kuziandika tena kwenye kumbukumbu ambayo inaweza kusaidia kuingiza mlango wa nyuma kwenye kifaa. Hivyo, kuna uwezekano mwingi ambao unaweza kufunguliwa kwa kutoa firmware.

### CH341A EEPROM Programmer and Reader

Kifaa hiki ni zana isiyo na gharama kubwa kwa kutoa firmwares kutoka EEPROMs na pia kuziandika tena na faili za firmware. Hii imekuwa chaguo maarufu kwa kufanya kazi na chips za BIOS za kompyuta (ambazo ni EEPROMs tu). Kifaa hiki kinaunganishwa kupitia USB na kinahitaji zana chache kuanza. Pia, kawaida kinamaliza kazi haraka, hivyo kinaweza kuwa na manufaa katika ufikiaji wa kifaa cha kimwili pia.

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

Unganisha kumbukumbu ya EEPROM na CH341a Programmer na uunganishi kifaa kwenye kompyuta. Ikiwa kifaa hakitambuliwi, jaribu kufunga madereva kwenye kompyuta. Pia, hakikisha kwamba EEPROM imeunganishwa kwa mwelekeo sahihi (kawaida, weka pini ya VCC katika mwelekeo wa kinyume na kiunganishi cha USB) la sivyo, programu haitakuwa na uwezo wa kutambua chip. Angalia mchoro ikiwa inahitajika:

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

Hatimaye, tumia programu kama flashrom, G-Flash (GUI), n.k. kwa ajili ya kutoa firmware. G-Flash ni zana ya GUI ndogo inayofanya kazi haraka na inatambua EEPROM kiotomatiki. Hii inaweza kuwa na manufaa ikiwa firmware inahitaji kutolewa haraka, bila kuingilia sana katika nyaraka.

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

Baada ya kutoa firmware, uchambuzi unaweza kufanywa kwenye faili za binary. Zana kama strings, hexdump, xxd, binwalk, n.k. zinaweza kutumika kutoa taarifa nyingi kuhusu firmware pamoja na mfumo mzima wa faili pia.

Ili kutoa maudhui kutoka kwa firmware, binwalk inaweza kutumika. Binwalk inachambua saini za hex na kutambua faili katika faili ya binary na ina uwezo wa kuzitoa.
```
binwalk -e <filename>
```
The can be .bin or .rom as per the tools and configurations used.

{% hint style="danger" %}
Kumbuka kwamba uchimbaji wa firmware ni mchakato wa nyeti na unahitaji uvumilivu mwingi. Kila makosa yanaweza kuharibu firmware au hata kuifuta kabisa na kufanya kifaa kisitumike. Inashauriwa kujifunza kuhusu kifaa maalum kabla ya kujaribu kuchimba firmware.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Kumbuka kwamba hata kama PINOUT ya Pirate Bus inaonyesha pini za **MOSI** na **MISO** kuunganishwa na SPI, hata hivyo baadhi ya SPIs zinaweza kuonyesha pini kama DI na DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

Katika Windows au Linux unaweza kutumia programu [**`flashrom`**](https://www.flashrom.org/Flashrom) kutupa maudhui ya kumbukumbu ya flash ukikimbia kitu kama:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
