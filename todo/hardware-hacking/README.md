# Kuvunja Vifaa

<details>

<summary><strong>Jifunze kuvunja AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvunja kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## JTAG

JTAG inaruhusu kufanya uchunguzi wa mpaka. Uchunguzi wa mpaka unachambua mzunguko fulani, ikiwa ni pamoja na seli za uchunguzi wa mpaka zilizojumuishwa na rejista kwa kila pin.

Kiwango cha JTAG kinadefini **maagizo maalum ya kufanya uchunguzi wa mpaka**, ikiwa ni pamoja na yafuatayo:

* **BYPASS** inaruhusu kujaribu chip maalum bila gharama ya kupitia chips zingine.
* **SAMPLE/PRELOAD** inachukua sampuli ya data inayoingia na kutoka kifaa wakati kinafanya kazi kawaida.
* **EXTEST** inaweka na kusoma hali za pini.

Pia inaweza kusaidia maagizo mengine kama vile:

* **IDCODE** kwa kutambua kifaa
* **INTEST** kwa uchunguzi wa ndani wa kifaa

Unaweza kukutana na maagizo haya unapotumia chombo kama JTAGulator.

### Bandari ya Upatikanaji wa Mtihani

Uchunguzi wa mpaka unajumuisha vipimo vya **Bandari ya Upatikanaji wa Mtihani (TAP)** ya nyaya nne, bandari ya matumizi ya jumla inayotoa **upatikanaji wa kusaidia mtihani wa JTAG** iliyojengwa ndani ya sehemu. TAP hutumia ishara tano zifuatazo:

* Kuingiza saa ya mtihani (**TCK**) TCK ni **saa** inayoeleza mara ngapi kudhibiti kifaa cha TAP kitachukua hatua moja (yaani, kwenda hatua inayofuata katika mashine ya hali).
* Kuchagua hali ya mtihani (**TMS**) Kuingiza TMS inadhibiti **mashine ya hali ya mwisho**. Kila wakati wa saa, kudhibiti cha TAP cha kifaa huchunguza voltage kwenye pini ya TMS. Ikiwa voltage iko chini ya kizingiti fulani, ishara inachukuliwa kuwa chini na kufasiriwa kama 0, wakati ikiwa voltage iko juu ya kizingiti fulani, ishara inachukuliwa kuwa juu na kufasiriwa kama 1.
* Kuingiza data ya mtihani (**TDI**) TDI ni pini inayotuma **data ndani ya chip kupitia seli za uchunguzi**. Kila muuzaji anahusika na kufafanua itifaki ya mawasiliano kupitia pini hii, kwa sababu JTAG haidefinishi hii.
* Kutoa data ya mtihani (**TDO**) TDO ni pini inayotuma **data nje ya chip**.
* Kuingiza upya mtihani (**TRST**) Kuingiza TRST inarejesha **mashine ya hali ya mwisho** kwa hali nzuri inayojulikana. Vinginevyo, ikiwa TMS inashikiliwa kwa 1 kwa mizunguko mitano ya saa, inaita upya, kama ilivyo kwa pini ya TRST, ndio sababu TRST ni hiari.

Maranyingi utaweza kupata pini hizo zilizowekwa alama kwenye PCB. Katika hali zingine unaweza kuhitaji **kuzipata**.

### Kutambua Pini za JTAG

Njia ya haraka lakini ghali zaidi ya kugundua bandari za JTAG ni kwa kutumia **JTAGulator**, kifaa kilichoundwa kwa kusudi hili (ingawa inaweza **pia kugundua mipangilio ya UART**).

Ina **vituo 24** unaweza kuunganisha kwenye pini za bodi. Kisha inafanya **shambulio la BF** la mchanganyiko wote uwezekanao kutuma maagizo ya uchunguzi wa mpaka ya **IDCODE** na **BYPASS**. Ikiipokea majibu, inaonyesha kituo kinacholingana na kila ishara ya JTAG

Njia nafuu lakini polepole zaidi ya kutambua mipangilio ya pini za JTAG ni kwa kutumia [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) iliyopakiwa kwenye kichapishi kinachoweza kufanana na Arduino.

Kwa kutumia **JTAGenum**, kwanza ungehitaji **kufafanua pini za kifaa cha uchunguzi** utakazotumia kwa uorodheshaji. Ungehitaji kurejelea ramani ya pini ya kifaa, kisha kuunganisha pini hizi na alama za majaribio kwenye kifaa chako lengwa.

Njia **ya tatu** ya kutambua pini za JTAG ni kwa **kuchunguza PCB** kwa moja ya mipangilio ya pini. Katika hali zingine, PCB inaweza kutoa **interface ya Tag-Connect** kwa urahisi, ambayo ni ishara wazi kwamba bodi ina kifaa cha JTAG, pia. Unaweza kuona jinsi interface hiyo inavyoonekana kwenye [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Aidha, kuchunguza **datasheets za chipsets kwenye PCB** kunaweza kufunua ramani za pini zinazoashiria viunganishi vya JTAG.

## SDW

SWD ni itifaki maalum ya ARM iliyoundwa kwa ajili ya kudebugi.

Interface ya SWD inahitaji **pini mbili**: ishara ya **SWDIO** inayoweza kubadilishana, ambayo ni sawa na pini za **TDI na TDO za JTAG na saa**, na **SWCLK**, ambayo ni sawa na **TCK** katika JTAG. Vifaa vingi vinaweza kusaidia **Bandari ya Upatikanaji wa Mfululizo au Debug ya JTAG (SWJ-DP)**, interface iliyounganisha JTAG na SWD inayokuwezesha kuunganisha kitanzi cha SWD au JTAG kwenye lengo. 

<details>

<summary><strong>Jifunze kuvunja AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvunja kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
