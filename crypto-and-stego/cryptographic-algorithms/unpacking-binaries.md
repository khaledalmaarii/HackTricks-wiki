<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# Kutambua faili zilizopakiwa

* **Ukosefu wa herufi**: Ni kawaida kukuta kuwa faili zilizopakiwa hazina herufi nyingi
* Wingi wa **herufi zisizotumiwa**: Pia, wakati programu hasidi inatumia aina fulani ya pakiti ya kibiashara, ni kawaida kukuta wingi wa herufi bila marejeo ya msalaba. Hata kama herufi hizi zipo, haimaanishi kuwa faili haijapakiwa.
* Unaweza pia kutumia zana fulani kujaribu kupata pakiti gani iliyotumiwa kufunga faili:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Mapendekezo ya Msingi

* **Anza** kuchambua faili iliyopakiwa **kutoka chini kwenda juu** kwenye IDA. Unpackers hutoka mara tu msimbo uliopakiwa unapoondoka, kwa hivyo ni jambo lisilowezekana kwamba unpacker atapitisha utekelezaji kwa msimbo uliopakiwa mwanzoni.
* Tafuta **JMP's** au **CALLs** kwa **registri** au **eneo** la **kumbukumbu**. Pia tafuta **kazi zinazosukuma hoja na anwani ya mwelekeo kisha kuita `retn`**, kwa sababu kurudi kwa kazi katika kesi hiyo kunaweza kuita anwani iliyoingizwa tu kwenye steki kabla ya kuita.
* Weka **kituo cha kusimamisha** kwenye `VirtualAlloc` kwani hii inatenga nafasi kwenye kumbukumbu ambapo programu inaweza kuandika msimbo uliopakiwa. "Kuendesha hadi msimbo wa mtumiaji" au tumia F8 **kufikia thamani ndani ya EAX** baada ya kutekeleza kazi na "**fuata anwani hiyo kwenye kumbukumbu**". Kamwe hujui ikiwa hiyo ndio eneo ambapo msimbo uliopakiwa utahifadhiwa.
* **`VirtualAlloc`** na thamani "**40**" kama hoja inamaanisha Soma+Andika+Tekeleza (baadhi ya msimbo unahitaji utekelezaji utahamishwa hapa).
* Wakati wa kufungua msimbo ni kawaida kupata **wito kadhaa** kwa **shughuli za hisabati** na kazi kama **`memcopy`** au **`Virtual`**`Alloc`. Ikiwa utakuta mwenyewe katika kazi ambayo inaonekana tu kufanya shughuli za hisabati na labda `memcopy` kadhaa, mapendekezo ni kujaribu **kupata mwisho wa kazi** (labda JMP au wito kwa baadhi ya usajili) **au** angalau **wito wa kazi ya mwisho** na kukimbia kisha kwa kuwa msimbo si wa kuvutia.
* Wakati wa kufungua msimbo **tambua** wakati wowote unapobadilisha **eneo la kumbukumbu** kwani mabadiliko ya eneo la kumbukumbu yanaweza kuashiria **kuanza kwa msimbo uliopakiwa**. Unaweza kudump eneo la kumbukumbu kwa urahisi kwa kutumia Process Hacker (mchakato -> mali -> kumbukumbu).
* Wakati unajaribu kufungua msimbo, njia nzuri ya **kujua ikiwa tayari unafanya kazi na msimbo uliopakiwa** (ili uweze tu kuudump) ni **kuchunguza herufi za faili**. Ikiwa kwa wakati fulani unafanya kuruka (labda kubadilisha eneo la kumbukumbu) na unagundua kuwa **wingi wa herufi umeongezwa**, basi unaweza kujua **unafanya kazi na msimbo uliopakiwa**.\
Hata hivyo, ikiwa pakiti tayari ina wingi wa herufi, unaweza kuona ni herufi ngapi zina neno "http" na uone ikiwa idadi hii inaongezeka.
* Unapodump faili ya kutekelezwa kutoka eneo la kumbukumbu, unaweza kurekebisha vichwa fulani kwa kutumia [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
