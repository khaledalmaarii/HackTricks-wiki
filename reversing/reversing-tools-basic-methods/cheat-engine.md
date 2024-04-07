# Cheat Engine

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ni programu muhimu ya kutafuta mahali ambapo thamani muhimu zimehifadhiwa ndani ya kumbukumbu ya mchezo unaoendelea na kuzibadilisha.\
Unapoidownload na kuikimbia, unapewa **mafunzo** ya jinsi ya kutumia zana hiyo. Ikiwa unataka kujifunza jinsi ya kutumia zana hiyo, ni vyema kumaliza mafunzo hayo.

## Unachotafuta ni nini?

![](<../../.gitbook/assets/image (759).png>)

Zana hii ni muhimu sana kwa kutafuta **mahali ambapo thamani fulani** (kawaida nambari) **imehifadhiwa kwenye kumbukumbu** ya programu.\
**Kawaida nambari** zimehifadhiwa kwa **muundo wa 4bytes**, lakini unaweza pia kuzipata kwa muundo wa **double** au **float**, au unaweza kutaka kutafuta kitu **tofauti na nambari**. Kwa sababu hiyo, ni muhimu kuhakikisha unachagua unachotaka **kutafuta**:

![](<../../.gitbook/assets/image (321).png>)

Pia unaweza kueleza **aina tofauti** za **utafutaji**:

![](<../../.gitbook/assets/image (307).png>)

Unaweza pia kuchagua sanduku la **kusimamisha mchezo wakati wa kutafuta kumbukumbu**:

![](<../../.gitbook/assets/image (1049).png>)

### Vitufe vya Haraka

Katika _**Hariri --> Vipangilio --> Vitufe vya Haraka**_ unaweza kuweka **vitufe vya haraka** tofauti kwa madhumuni tofauti kama **kusimamisha** **mchezo** (ambao ni muhimu ikiwa wakati fulani unataka kutafuta kumbukumbu). Chaguo nyingine zinapatikana:

![](<../../.gitbook/assets/image (861).png>)

## Kubadilisha thamani

Maranyingine unapopata **mahali** ambapo **thamani** unayoitafuta ipo (zaidi kuhusu hili katika hatua zifuatazo) unaweza kuibadilisha kwa kubofya mara mbili, kisha kubofya mara mbili thamani yake:

![](<../../.gitbook/assets/image (560).png>)

Na mwishowe **tia alama ya tiki** ili kufanya mabadiliko kwenye kumbukumbu:

![](<../../.gitbook/assets/image (382).png>)

Mabadiliko kwenye **kumbukumbu** yatakuwa mara moja **yamefanyika** (tambua kuwa hadi mchezo hautumii tena thamani hii, thamani **haitasasishwa kwenye mchezo**).

## Kutafuta thamani

Kwa hivyo, tutachukulia kuwa kuna thamani muhimu (kama maisha ya mtumiaji wako) unayotaka kuboresha, na unatafuta thamani hii kwenye kumbukumbu)

### Kupitia mabadiliko yanayojulikana

Ukichukulia unatafuta thamani 100, unafanya **utafutaji** ukatafuta thamani hiyo na unapata matokeo mengi yanayofanana:

![](<../../.gitbook/assets/image (105).png>)

Kisha, fanya kitu ili **thamani ibadilike**, na **sima** mchezo na **fanya** **utafutaji unaofuata**:

![](<../../.gitbook/assets/image (681).png>)

Cheat Engine itatafuta **thamani** zilizobadilika kutoka 100 kwenda thamani mpya. Hongera, umepata **anwani** ya thamani uliyokuwa ukiiangalia, sasa unaweza kuibadilisha.\
_Ikiwa bado una thamani kadhaa, fanya kitu kingine kubadilisha tena thamani hiyo, na fanya "utafutaji unaofuata" mwingine ili kuchuja anwani._

### Thamani Isiyojulikana, mabadiliko yanayojulikana

Katika hali ambayo **hujui thamani** lakini unajua **jinsi ya kufanya ibadilike** (na hata thamani ya mabadiliko) unaweza kutafuta nambari yako.

Kwa hivyo, anza kwa kufanya utafutaji wa aina "**Thamani ya Awali Isiyojulikana**":

![](<../../.gitbook/assets/image (887).png>)

Kisha, fanya thamani ibadilike, eleza **jinsi** **thamani** **ilibadilika** (kwa mfano kwangu ilipunguzwa kwa 1) na fanya **utafutaji unaofuata**:

![](<../../.gitbook/assets/image (368).png>)

Utapewa **thamani zote zilizobadilishwa kwa njia iliyochaguliwa**:

![](<../../.gitbook/assets/image (566).png>)

Maranyingine kuna **mabadiliko mengi yanayowezekana** na unaweza kufanya hatua hizi **kadri unavyotaka** kuchuja matokeo:

![](<../../.gitbook/assets/image (571).png>)

### Anwani ya Kumbukumbu Isiyotabirika - Kupata nambari

Mpaka sasa tumepata jinsi ya kupata anwani inayohifadhi thamani, lakini ni uwezekano mkubwa kwamba katika **utekelezaji tofauti wa mchezo anwani hiyo iko sehemu tofauti ya kumbukumbu**. Hebu tujue jinsi ya kutafuta daima anwani hiyo.

Kwa kutumia mbinu zilizotajwa, pata anwani ambapo mchezo wako wa sasa unahifadhi thamani muhimu. Kisha (kusimamisha mchezo ikiwa unataka) bofya kulia kwenye anwani uliyoipata na chagua "**Gundua nini kinatumia anwani hii**" au "**Gundua nini kinachoandika kwenye anwani hii**":

![](<../../.gitbook/assets/image (1064).png>)

**Chaguo la kwanza** ni muhimu kujua ni **vipande** vipi vya **mimba** vinavyotumia **anwani hii** (ambayo ni muhimu kwa mambo zaidi kama **kujua wapi unaweza kubadilisha kanuni** ya mchezo).\
**Chaguo la pili** ni **maalum zaidi**, na litakuwa na manufaa zaidi katika kesi hii kwani tunataka kujua **kutoka wapi thamani hii inaandikwa**.

Baada ya kuchagua moja ya chaguo hizo, **mchunguzi** utaunganishwa kwenye programu na dirisha jipya **tupu** litatokea. Sasa, **cheza** mchezo na **badilisha** thamani hiyo (bila kuanzisha upya mchezo). **Dirisha** linapaswa **kujazwa** na **anwani** zinazobadilisha **thamani**:

![](<../../.gitbook/assets/image (88).png>)

Sasa ulipogundua anwani inayobadilisha thamani unaweza **kubadilisha kanuni kwa furaha** (Cheat Engine inakuruhusu kubadilisha kwa NOPs haraka):

![](<../../.gitbook/assets/image (1054).png>)

Kwa hivyo, unaweza kubadilisha ili kanuni isiathiri nambari yako, au itaathiri daima kwa njia chanya.
### Anwani ya Kumbukumbu Isiyotabirika - Kupata kielekezi

Kufuatia hatua zilizopita, pata mahali ambapo thamani unayopendezwa nayo iko. Kisha, kutumia "**Pata ni nani anayeandika kwenye anwani hii**" jua ni anwani gani inayoandika thamani hii na bofya mara mbili ili upate maoni ya kufasiri:

![](<../../.gitbook/assets/image (1036).png>)

Kisha, fanya utafutaji mpya **ukitafuta thamani ya hex kati ya "\[]"** (thamani ya $edx katika kesi hii):

![](<../../.gitbook/assets/image (991).png>)

(_Ikiwa zinaonekana kadhaa, kawaida unahitaji ile yenye anwani ndogo zaidi_)\
Sasa, tumepata **kielekezi ambacho kitabadilisha thamani tunayopendezwa nayo**.

Bofya "**Ongeza Anwani Manually**":

![](<../../.gitbook/assets/image (987).png>)

Sasa, bofya kisanduku cha "Kielekezi" na ongeza anwani iliyopatikana kwenye sanduku la maandishi (katika hali hii, anwani iliyopatikana kwenye picha iliyopita ilikuwa "Mafunzo-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (388).png>)

(Tazama jinsi "Anwani" ya kwanza inavyojazwa moja kwa moja kutoka kwa anwani ya kielekezi unayoingiza)

Bofya OK na kielekezi kipya kitabuni:

![](<../../.gitbook/assets/image (305).png>)

Sasa, kila wakati unabadilisha thamani hiyo un **kubadilisha thamani muhimu hata ikiwa anwani ya kumbukumbu ambapo thamani iko ni tofauti.**

### Uingizaji wa Kanuni

Uingizaji wa kanuni ni mbinu ambapo unainjekta kipande cha kanuni ndani ya mchakato lengwa, na kisha kurekebisha utekelezaji wa kanuni kwenda kupitia kanuni uliyoandika mwenyewe (kama kukupa alama badala ya kuzipunguza).

Kwa hivyo, wazia umepata anwani inayopunguza 1 kwa maisha ya mchezaji wako:

![](<../../.gitbook/assets/image (200).png>)

Bofya Onyesha kufasiri ili upate **kanuni ya kufasiri**.\
Kisha, bofya **CTRL+a** kuita dirisha la Kujumuisha Kiotomatiki na chagua _**Kiolezo --> Uingizaji wa Kanuni**_

![](<../../.gitbook/assets/image (899).png>)

Jaza **anwani ya maagizo unayotaka kurekebisha** (kawaida hii inajazwa moja kwa moja):

![](<../../.gitbook/assets/image (741).png>)

Kiolezo kitabuni:

![](<../../.gitbook/assets/image (941).png>)

Kwa hivyo, ingiza kanuni yako mpya ya mkusanyiko katika sehemu ya "**newmem**" na ondoa kanuni ya asili kutoka kwa "**originalcode**" ikiwa hautaki iendelee kutekelezwa\*\*.\*\* Katika mfano huu, kanuni iliyoinjekta itaongeza alama 2 badala ya kupunguza 1:

![](<../../.gitbook/assets/image (518).png>)

**Bofya kutekeleza na kadhalika na kanuni yako itapaswa kuingizwa kwenye programu ikibadilisha tabia ya utendaji!**

## **Vyanzo**

* **Mafunzo ya Cheat Engine, kamilisha ili ujifunze jinsi ya kuanza na Cheat Engine**
