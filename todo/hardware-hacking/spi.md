<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# Taarifa Msingi

SPI (Serial Peripheral Interface) ni Itifaki ya Mawasiliano ya Serial ya Synchronous inayotumiwa katika mifumo iliyowekwa kwa mawasiliano ya umbali mfupi kati ya ICs (Machipukizi Yaliyounganishwa). Itifaki ya Mawasiliano ya SPI hutumia usanifu wa bwana-mtumwa ambao unasimamiwa na Saa na Ishara ya Kuchagua Chip. Usanifu wa bwana-mtumwa unajumuisha bwana (kawaida ni microprocessor) ambayo inasimamia vifaa vya nje kama EEPROM, sensori, vifaa vya kudhibiti, nk. ambavyo huchukuliwa kuwa watumwa.

Watumwa wengi wanaweza kuunganishwa kwa bwana lakini watumwa hawawezi kuzungumza na wao wenyewe. Watumwa wanatunzwa na pini mbili, saa na kuchagua chip. Kwa kuwa SPI ni itifaki ya mawasiliano ya synchronous, pini za kuingia na kutoa zifuata ishara za saa. Kuchagua chip hutumiwa na bwana kuchagua mtumwa na kuingiliana naye. Wakati kuchagua chip iko juu, kifaa cha mtumwa hakijachaguliwa wakati inapokuwa chini, chip imechaguliwa na bwana atakuwa anaingiliana na mtumwa.

MOSI (Bwana Nje, Mtumwa Ndani) na MISO (Bwana Ndani, Mtumwa Nje) wanahusika na kutuma na kupokea data. Data hutumwa kwa kifaa cha mtumwa kupitia pini ya MOSI wakati kuchagua chip inashikiliwa chini. Data ya kuingia ina maagizo, anwani za kumbukumbu au data kulingana na karatasi ya data ya muuzaji wa kifaa cha mtumwa. Kwa kuingia sahihi, pini ya MISO inahusika na kutuma data kwa bwana. Data ya kutoa hutumwa moja kwa moja kwenye mzunguko wa saa baada ya kuingia kuisha. Pini za MISO hutoa data hadi data itakapotumwa kabisa au bwana anaweka pini ya kuchagua chip juu (katika kesi hiyo, mtumwa atakoma kutuma na bwana hataisikiliza baada ya mzunguko huo wa saa).

# Tupa Flash

## Bus Pirate + flashrom

![](<../../.gitbook/assets/image (201).png>)

Tafadhali kumbuka hata kama PINOUT ya Pirate Bus inaonyesha pini za **MOSI** na **MISO** kuunganishwa kwa SPI hata hivyo baadhi ya SPI inaweza kuonyesha pini kama DI na DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (648) (1) (1).png>)

Katika Windows au Linux unaweza kutumia programu [**`flashrom`**](https://www.flashrom.org/Flashrom) kudumpisha maudhui ya kumbukumbu ya flash kwa kukimbia kitu kama:
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
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
