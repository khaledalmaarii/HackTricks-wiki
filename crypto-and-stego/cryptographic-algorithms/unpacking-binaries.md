<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# Kutambua binaries zilizofungwa

* **Ukosefu wa strings**: Ni kawaida kupata kuwa binaries zilizofungwa hazina karibu string yoyote
* Wingi wa **strings zisizotumiwa**: Pia, wakati programu hasidi inatumia aina fulani ya pakiti ya kibiashara ni kawaida kupata wingi wa strings bila marejeo ya msalaba. Hata kama strings hizi zipo haimaanishi kuwa binary haifungwi.
* Unaweza pia kutumia zana fulani kujaribu kugundua ni pakiti ipi iliyotumiwa kufunga binary:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Mapendekezo ya Msingi

* **Anza** kuchambua binary iliyofungwa **kutoka chini katika IDA na endelea juu**. Unpackers hutokea mara tu msimbo uliofunguliwa unapoisha hivyo ni nadra kwamba unpacker atapitisha utekelezaji kwa msimbo uliofunguliwa mwanzoni.
* Tafuta **JMP's** au **CALLs** kwa **registers** au **mikoa** ya **kumbukumbu**. Pia tafuta **kazi zinazosukuma hoja na anwani ya kuelekeza kisha kuita `retn`**, kwa sababu kurudi kwa kazi katika kesi hiyo inaweza kuita anwani iliyosukumwa kwenye steki kabla ya kuipiga.
* Weka **kizuizi** kwenye `VirtualAlloc` kwani hii hutoa nafasi kwenye kumbukumbu ambapo programu inaweza kuandika msimbo uliofunguliwa. "kimbia kwa msimbo wa mtumiaji" au tumia F8 **kufikia thamani ndani ya EAX** baada ya kutekeleza kazi na "**fuata anwani hiyo kwenye dump**". Huwezi kujua ikiwa hiyo ndio eneo ambapo msimbo uliofunguliwa utahifadhiwa.
* **`VirtualAlloc`** na thamani "**40**" kama hoja inamaanisha Soma+Andika+Tekeleza (baadhi ya msimbo unahitaji utekelezaji utakaoandikwa hapa).
* Wakati wa kufungua msimbo ni kawaida kupata **wito kadhaa** kwa **shughuli za hisabati** na kazi kama **`memcopy`** au **`Virtual`**`Alloc`. Ikiwa utajikuta katika kazi ambayo inaonekana kufanya shughuli za hisabati tu na labda baadhi ya `memcopy`, mapendekezo ni kujaribu **kupata mwisho wa kazi** (labda JMP au wito kwa baadhi ya usajili) **au** angalau **wito wa mwisho** na kutekeleza kisha kwa kuwa msimbo si wa kuvutia.
* Wakati wa kufungua msimbo **tambua** kila wakati **unapobadilisha eneo la kumbukumbu** kwani mabadiliko ya eneo la kumbukumbu yanaweza kuashiria **kuanza kwa msimbo uliofunguliwa**. Unaweza kudump eneo la kumbukumbu kwa urahisi kwa kutumia Process Hacker (mchakato --> mali --> kumbukumbu).
* Wakati unajaribu kufungua msimbo njia nzuri ya **kujua ikiwa tayari unafanya kazi na msimbo uliofunguliwa** (hivyo unaweza tu kuudump) ni **kuchunguza strings za binary**. Ikiwa kwa wakati fulani unafanya kuruka (labda kubadilisha eneo la kumbukumbu) na unagundua kuwa **strings nyingi zimeongezwa**, basi unaweza kujua **unafanya kazi na msimbo uliofunguliwa**.\
Hata hivyo, ikiwa pakiti tayari ina strings nyingi unaweza kuona ni strings ngapi zina neno "http" na uone ikiwa idadi hii inaongezeka.
* Unapodumpa faili kutoka eneo la kumbukumbu unaweza kurekebisha vichwa fulani kwa kutumia [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
