<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kupata mahali ambapo thamani muhimu zimehifadhiwa ndani ya kumbukumbu ya mchezo unaofanya kazi na kuzibadilisha.\
Unapopakua na kuendesha programu hiyo, utapewa mafunzo juu ya jinsi ya kutumia zana hiyo. Ikiwa unataka kujifunza jinsi ya kutumia zana hiyo, ni muhimu sana kukamilisha mafunzo hayo.

# Unatafuta nini?

![](<../../.gitbook/assets/image (580).png>)

Zana hii ni muhimu sana kupata **mahali ambapo thamani fulani** (kawaida ni nambari) **imehifadhiwa kwenye kumbukumbu** ya programu.\
**Kawaida nambari** zimehifadhiwa kwa **muundo wa 4bytes**, lakini unaweza pia kuzipata kwa muundo wa **double** au **float**, au unaweza kutaka kutafuta kitu **tofauti na nambari**. Kwa sababu hiyo, ni muhimu kuhakikisha unachagua kile unachotaka kutafuta:

![](<../../.gitbook/assets/image (581).png>)

Pia unaweza kuonyesha **aina tofauti** za **utafutaji**:

![](<../../.gitbook/assets/image (582).png>)

Unaweza pia kuweka alama kwenye sanduku ili **kusimamisha mchezo wakati wa kutafuta kumbukumbu**:

![](<../../.gitbook/assets/image (584).png>)

## Vitenzi vya Haraka

Katika _**Hariri --> Mipangilio --> Vitenzi vya Haraka**_ unaweza kuweka **vitenzi vya haraka** tofauti kwa madhumuni tofauti kama **kusimamisha** mchezo (ambayo ni muhimu ikiwa wakati fulani unataka kutafuta kumbukumbu). Chaguo zingine zinapatikana:

![](<../../.gitbook/assets/image (583).png>)

# Kubadilisha thamani

Marafiki umepata **mahali ambapo thamani** unayotafuta (zaidi kuhusu hii katika hatua zifuatazo) unaweza **kuibadilisha** kwa kubofya mara mbili, kisha kubofya mara mbili thamani yake:

![](<../../.gitbook/assets/image (585).png>)

Na hatimaye **weka alama** ili kufanya mabadiliko kwenye kumbukumbu:

![](<../../.gitbook/assets/image (586).png>)

Mabadiliko kwenye kumbukumbu yatafanywa mara moja (kumbuka kuwa hadi mchezo hautumii tena thamani hii, thamani **haitasasishwa kwenye mchezo**).

# Kutafuta thamani

Kwa hivyo, tutafanya kudhani kuwa kuna thamani muhimu (kama maisha ya mtumiaji wako) ambayo unataka kuboresha, na unatafuta thamani hii kwenye kumbukumbu)

## Kupitia mabadiliko yanayojulikana

Kukisia kuwa unatafuta thamani 100, unafanya **utafutaji** ukatafuta thamani hiyo na unapata matokeo mengi yanayofanana:

![](<../../.gitbook/assets/image (587).png>)

Kisha, fanya kitu ili **thamani ibadilike**, na **sima** mchezo na **fanya** utafutaji **uendeleo**:

![](<../../.gitbook/assets/image (588).png>)

Cheat Engine itatafuta **thamani** ambazo **zilibadilika kutoka 100 hadi thamani mpya**. Hongera, umepata **anwani** ya thamani uliyokuwa ukiitafuta, sasa unaweza kuibadilisha.\
_Ikiwa bado una anwani kadhaa, fanya kitu kingine ili kubadilisha tena thamani hiyo, na fanya utafutaji mwingine wa "next scan" ili kuchuja anwani._

## Thamani Isiyojulikana, mabadiliko yanayojulikana

Katika hali ambayo **hujui thamani** lakini unajua **jinsi ya kufanya mabadiliko** (na hata thamani ya mabadiliko), unaweza kutafuta nambari yako.

Kwa hivyo, anza kwa kufanya utafutaji wa aina "**Thamani ya awali isiyojulikana**":

![](<../../.gitbook/assets/image (589).png>)

Kisha, fanya mabadiliko ya thamani, eleza **jinsi** thamani **ilibadilika** (katika kesi yangu ilipungua kwa 1) na fanya **utafutaji uendeleo**:

![](<../../.gitbook/assets/image (590).png>)

Utapewa **thamani zote zilizobadilishwa kwa njia iliyochaguliwa**:

![](<../../.gitbook/assets/image (591).png>)

Marafiki umepata thamani yako, unaweza kuibadilisha.

Kumbuka kuwa kuna **mabadiliko mengi yanayowezekana** na unaweza kufanya hatua hizi **kwa kadri unavyotaka** ili kuchuja matokeo:

![](<../../.gitbook/assets/image (592).png>)

## Anwani Isiyotabirika ya Kumbukumbu - Kupata nambari

Hadi sasa tumefunzwa jinsi ya kupata anwani inayohifadhi thamani, lakini ni kawaida sana kuwa katika **utekelezaji tofauti wa mchezo anwani hiyo iko sehemu tofauti ya kumbukumbu**. Kwa hivyo hebu tujue jinsi ya kupata anwani hiyo kila wakati.

Kwa kutumia mbinu zilizotajwa, pata anwani ambapo mchezo wako wa sasa unahifadhi thamani muhimu. Kisha (kusimamisha mchezo ikiwa unataka) bofya **click ya kulia** kwenye anwani iliyopatikana na chagua "**Pata ni nini kinachotumia anwani hii**" au "**Pata ni nini kinachoandika kwenye anwani hii**":

![](<../../.gitbook/assets/image (593).png>)

**Chaguo la kwanza** ni muhimu kujua ni **sehemu gani** za **kificho** zinatumia **anwani** hii (ambayo ni muhimu kwa mambo zaidi kama **kujua wapi unaweza kubadilisha kificho** cha mchezo).\
**Chaguo la pili** ni **maalum zaidi**, na litakuwa na manufaa zaidi katika kesi hii kwani tunataka kujua **kutoka wapi thamani hii inaandikwa**.

Baada ya kuchagua moja ya chaguo hizo, **mchunguzi** atakuwa **ameunganishwa** na programu na dirisha jipya **tupu** litatokea. Sasa, **cheza** mchezo na **badilisha** thamani hiyo (bila kuanza tena mche
## Anwani ya Kumbukumbu Isiyotabirika - Kupata Kiashiria

Kufuatia hatua za awali, tafuta mahali ambapo thamani unayopendezwa nayo iko. Kisha, kwa kutumia "**Pata ni nini kinachoandika kwenye anwani hii**" gundua anwani ambayo inaandika thamani hii na bonyeza mara mbili ili upate mtazamo wa kuvunja:

![](<../../.gitbook/assets/image (596).png>)

Kisha, fanya utafutaji mpya **ukitafuta thamani ya hex kati ya "\[]"** (thamani ya $edx katika kesi hii):

![](<../../.gitbook/assets/image (597).png>)

(Ikiwa zinatokea kadhaa, kawaida unahitaji ile yenye anwani ndogo zaidi)\
Sasa, tume**pata kiashiria ambacho kitabadilisha thamani tunayopendezwa nayo**.

Bonyeza "**Ongeza Anwani Kwa Mkono**":

![](<../../.gitbook/assets/image (598).png>)

Sasa, bonyeza kisanduku cha "Kiashiria" na ongeza anwani iliyopatikana kwenye sanduku la maandishi (katika kesi hii, anwani iliyopatikana kwenye picha iliyotangulia ilikuwa "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (599).png>)

(Angalia jinsi "Anwani" ya kwanza inavyojazwa moja kwa moja kutoka kwa anwani ya kiashiria unayoingiza)

Bonyeza OK na kiashiria kipya kitatengenezwa:

![](<../../.gitbook/assets/image (600).png>)

Sasa, kila wakati unabadilisha thamani hiyo unakuwa **unabadilisha thamani muhimu hata ikiwa anwani ya kumbukumbu ambapo thamani iko ni tofauti.**

## Uingizaji wa Kanuni

Uingizaji wa kanuni ni mbinu ambapo unaingiza kipande cha kanuni ndani ya mchakato wa lengo, na kisha kuelekeza utekelezaji wa kanuni kupitia kanuni uliyoandika mwenyewe (kama kukupa alama badala ya kuzipunguza).

Kwa hivyo, fikiria umepata anwani ambayo inapunguza 1 kwenye maisha ya mchezaji wako:

![](<../../.gitbook/assets/image (601).png>)

Bonyeza Onyesha kuvunja kanuni ili upate **kanuni ya kuvunja**.\
Kisha, bonyeza **CTRL+a** ili kuita dirisha la Kuingiza Kiotomatiki na chagua _**Kiolezo --> Uingizaji wa Kanuni**_

![](<../../.gitbook/assets/image (602).png>)

Jaza **anwani ya maagizo unayotaka kubadilisha** (kawaida inajazwa moja kwa moja):

![](<../../.gitbook/assets/image (603).png>)

Kiolezo kitazalishwa:

![](<../../.gitbook/assets/image (604).png>)

Kwa hivyo, ingiza kanuni yako mpya ya mkutano katika sehemu ya "**newmem**" na ondoa kanuni ya asili kutoka kwa "**originalcode**" ikiwa hautaki iwe inatekelezwa**.** Katika mfano huu, kanuni iliyochomwa itaongeza alama 2 badala ya kuzipunguza 1:

![](<../../.gitbook/assets/image (605).png>)

**Bonyeza kutekeleza na kadhalika na kanuni yako inapaswa kuingizwa kwenye programu ikibadilisha tabia ya kazi!**

# **Marejeo**

* **Mafunzo ya Cheat Engine, kamilisha ili kujifunza jinsi ya kuanza na Cheat Engine**



<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa katika HackTricks** au **kupakua HackTricks katika PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
