<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


#

# JTAG

JTAG inaruhusu kufanya uchunguzi wa mipaka. Uchunguzi wa mipaka huchambua mzunguko fulani, ikiwa ni pamoja na seli za uchunguzi wa mipaka iliyowekwa na usajili kwa kila pin.

Kiwango cha JTAG kinatambua **amri maalum za kufanya uchunguzi wa mipaka**, ikiwa ni pamoja na zifuatazo:

* **BYPASS** inakuwezesha kufanya jaribio la chip maalum bila gharama ya kupita kwenye chips nyingine.
* **SAMPLE/PRELOAD** inachukua sampuli ya data inayoingia na kutoka kwenye kifaa wakati kinafanya kazi kawaida.
* **EXTEST** inaweka na kusoma hali za pin.

Pia inaweza kusaidia amri zingine kama vile:

* **IDCODE** kwa kutambua kifaa
* **INTEST** kwa uchunguzi wa ndani wa kifaa

Unaweza kukutana na maagizo haya unapotumia zana kama JTAGulator.

## Bandari ya Upatikanaji wa Jaribio

Uchunguzi wa mipaka unajumuisha vipimo vya **Bandari ya Upatikanaji wa Jaribio (TAP)** yenye waya nne, bandari ya matumizi ya jumla ambayo hutoa **upatikanaji wa msaada wa jaribio la JTAG** uliojengwa ndani ya kipengele. TAP hutumia ishara tano zifuatazo:

* Kuingiza saa ya jaribio (**TCK**) TCK ni **saa** inayofafanua mara ngapi kudhibiti TAP itachukua hatua moja (yaani, kuruka hadi hali inayofuata katika mashine ya hali).
* Kuchagua hali ya jaribio (**TMS**) kuingiza TMS inadhibiti **mashine ya hali ya mwisho**. Kila wakati saa inapopiga, kudhibiti TAP ya JTAG ya kifaa huchunguza voltage kwenye pin ya TMS. Ikiwa voltage iko chini ya kizingiti fulani, ishara inachukuliwa kuwa ya chini na kusomwa kama 0, wakati ikiwa voltage iko juu ya kizingiti fulani, ishara inachukuliwa kuwa ya juu na kusomwa kama 1.
* Kuingiza data ya jaribio (**TDI**) TDI ni pin inayotuma **data kwenye chip kupitia seli za uchunguzi**. Kila muuzaji anawajibika kufafanua itifaki ya mawasiliano juu ya pin hii, kwa sababu JTAG haifafanui hii.
* Kutoa data ya jaribio (**TDO**) TDO ni pin inayotuma **data kutoka kwenye chip**.
* Kuingiza upya jaribio (**TRST**) kuingiza TRST ya hiari inarejesha mashine ya hali ya mwisho **kwenye hali nzuri inayojulikana**. Vinginevyo, ikiwa TMS inashikiliwa kwa 1 kwa mizunguko mitano ya saa mfululizo, inaita upya, kwa njia ile ile pin ya TRST ingefanya, ndio maana TRST ni ya hiari.

Marafiki wakati mwingine utaweza kupata pini hizo zilizochorwa kwenye PCB. Katika hali zingine, unaweza kuhitaji **kuzipata**.

## Kutambua pini za JTAG

Njia ya haraka lakini ghali zaidi ya kugundua bandari za JTAG ni kwa kutumia **JTAGulator**, kifaa kilichoundwa kwa kusudi hili (ingawa pia kinaweza **kugundua pinouts za UART**).

Ina **njia 24** unaweza kuunganisha kwenye pini za bodi. Kisha inatekeleza shambulio la **BF** kwa mchanganyiko wote unaowezekana ukituma amri za uchunguzi wa mipaka za **IDCODE** na **BYPASS**. Ikiwa inapokea jibu, inaonyesha njia inayolingana na kila ishara ya JTAG.

Njia nyingine ya bei rahisi lakini polepole sana ya kutambua pinouts za JTAG ni kwa kutumia [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) iliyopakiwa kwenye kifaa kinachofanana na Arduino.

Kutumia **JTAGenum**, kwanza unapaswa **kuamua pini za kifaa cha uchunguzi** utakazotumia kwa uorodheshaji. Lazima utaje ramani ya pinout ya kifaa, kisha unganisha pini hizi na alama za jaribio kwenye kifaa chako lengwa.

Njia ya **tatu** ya kutambua pini za JTAG ni kwa **kuchunguza PCB** kwa moja ya pinouts. Katika baadhi ya kesi, PCB inaweza kutoa **interface ya Tag-Connect**, ambayo ni ishara wazi kwamba bodi ina kifaa cha JTAG pia. Unaweza kuona jinsi interface hiyo inavyoonekana kwenye [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Aidha, kuchunguza **datasheets za chipsets kwenye PCB** kunaweza kufunua ramani za pinout zinazoashiria interfaces za JTAG.

# SDW

SWD ni itifaki maalum ya ARM iliyoundwa kwa ajili ya uchunguzi wa kosa.

Kiolesura cha SWD kinahitaji **pini mbili**: ishara ya SWDIO inayoweza kusoma na kuandika, ambayo ni sawa na pini za **TDI na TDO za JTAG na saa**, na **SWCLK**, ambayo ni sawa na **TCK** katika JTAG. Vifaa vingi vinaweza kusaidia **Bandari ya Uchunguzi ya Mstari wa Mfululizo au JTAG (SWJ-DP)**, kiolesura kilichounganisha JTAG na SWD ambacho kinakuwezesha kuunganisha kifaa cha SWD au JTAG kwenye lengo.


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kud
