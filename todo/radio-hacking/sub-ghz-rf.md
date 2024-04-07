# Sub-GHz RF

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Milango ya Gari

Wafunguo wa milango ya gari kawaida hufanya kazi kwenye masafa ya 300-190 MHz, na masafa yanayotumika zaidi ni 300 MHz, 310 MHz, 315 MHz, na 390 MHz. Masafa haya yanatumika kwa kawaida kwa wafunguo wa milango ya gari kwa sababu ni machache kuliko masafa mengine na hayana uwezekano mkubwa wa kuingiliwa na vifaa vingine.

## Milango ya Gari

Wafunguo wengi wa gari hufanya kazi kwenye masafa ya **315 MHz au 433 MHz**. Hizi ni masafa ya redio, na hutumiwa katika matumizi mbalimbali. Tofauti kuu kati ya masafa haya mawili ni kwamba 433 MHz ina mbalimbali kubwa kuliko 315 MHz. Hii inamaanisha kuwa 433 MHz ni bora kwa matumizi yanayohitaji mbalimbali kubwa, kama vile kuingia kwa mbali bila kutumia ufunguo.\
Ulaya hutumia 433.92MHz kwa kawaida na Marekani na Japani hutumia 315MHz.

## **Shambulio la Brute-force**

<figure><img src="../../.gitbook/assets/image (1081).png" alt=""><figcaption></figcaption></figure>

Badala ya kutuma kila nambari mara 5 (kutumwa hivi ili kuhakikisha mpokeaji anapata) basi itume mara moja, muda unapunguzwa hadi dakika 6:

<figure><img src="../../.gitbook/assets/image (616).png" alt=""><figcaption></figcaption></figure>

na ikiwa **ondoa kipindi cha kusubiri cha 2 ms** kati ya ishara unaweza **kupunguza muda hadi dakika 3**.

Zaidi, kwa kutumia Mfululizo wa De Bruijn (njia ya kupunguza idadi ya bits inayohitajika kutuma nambari zote za binary zinazowezekana kwa kudukua) **muda huu unapunguzwa hadi sekunde 8**:

<figure><img src="../../.gitbook/assets/image (580).png" alt=""><figcaption></figcaption></figure>

Mfano wa shambulio hili ulitekelezwa katika [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Kuhitaji **kipande cha awali** kutazuia upimaji wa Mfululizo wa De Bruijn na **nambari za kubadilika zitazuia shambulio hili** (ikiwa nambari ni ndefu vya kutosha kutoweza kudukuliwa).

## Shambulio la Sub-GHz

Kudukua ishara hizi na Flipper Zero angalia:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Ulinzi wa Nambari za Kubadilika

Wafunguo wa milango ya gari ya kiotomatiki kwa kawaida hutumia kudhibiti mbali wa redio ili kufungua na kufunga mlango wa gari. Kudhibiti mbali **hutuma ishara ya redio (RF)** kwa kifungua mlango wa gari, ambacho huanzisha injini kufungua au kufunga mlango.

Inawezekana kwa mtu kutumia kifaa kinachoitwa kuchukua nambari kudaka ishara ya RF na kuirekodi kwa matumizi baadaye. Hii inajulikana kama **shambulio la kurudia**. Ili kuzuia aina hii ya shambulio, wafungua milango ya gari ya kisasa hutumia njia salama zaidi ya kuficha inayoitwa mfumo wa **nambari za kubadilika**.

**Ishara ya RF kwa kawaida hutumwa kwa kutumia nambari za kubadilika**, maana yake ni kwamba nambari inabadilika kila inapotumiwa. Hii inafanya iwe **ngumu** kwa mtu yeyote **kuchukua** ishara na **kuitumia** kupata **upatikanaji usioidhinishwa** wa gari.

Katika mfumo wa nambari za kubadilika, kudhibiti mbali na kifungua mlango wa gari wana **algoritimu inayoshirikiana** ambayo **inazalisha nambari mpya** kila wakati kifungua mbali kinapotumiwa. Kifungua mlango wa gari kitajibu tu kwa **nambari sahihi**, hivyo kufanya iwe ngumu zaidi kwa mtu kupata upatikanaji usioidhinishwa wa gari kwa kuchukua nambari.

### **Shambulio la Kiungo Kilichopotea**

Kimsingi, unalisikiliza kifungo na **kuchukua ishara wakati kifungua mbali kiko nje ya mbali** ya kifaa (kama gari au garaji). Kisha unahamia kwenye kifaa na **kutumia nambari uliyochukua kufungua**.

### Shambulio Kamili la Kuzuia Kiungo

Mshambuliaji anaweza **kuzuia ishara karibu na gari au mpokeaji** ili **mpokeaji asisikie kweli nambari**, na mara tu hilo linapotokea unaweza tu **kuchukua na kurudia** nambari unapomaliza kuzuia.

Mkosa atafikia wakati fulani atatumia **funguo kufunga gari**, lakini kisha shambulio litakuwa **limeirekodi "nambari za kufunga" za kutosha** ambazo kwa matumaini zinaweza kutumwa tena kufungua mlango (inaweza kuhitajika **mabadiliko ya masafa** kwani kuna magari yanayotumia nambari sawa kufungua na kufunga lakini yanasikiliza amri zote kwa masafa tofauti).

{% hint style="warning" %}
**Kuzuia kazi**, lakini ni dhahiri kama **mtu anayefunga gari anajaribu tu milango** kuhakikisha wamefungwa wangeweza kugundua gari halijafungwa. Aidha, kama wangekuwa na ufahamu wa mashambulio kama hayo wangeweza hata kusikiliza ukweli kwamba milango haikufanya sauti ya kufunga au **taa za gari** hazikutoa ishara wakati walipobonyeza kitufe cha ‘funga’.
{% endhint %}

### **Shambulio la Kuchukua Nambari (inayoitwa ‘RollJam’)**

Hii ni mbinu ya **kuzuia yenye siri zaidi**. Mshambuliaji atazuia ishara, hivyo wakati muhanga anajaribu kufunga mlango haitafanya kazi, lakini mshambuliaji atakay **kurekodi nambari hii**. Kisha, muhanga atajaribu kufunga gari tena kwa kubonyeza kitufe na gari itarekodi **nambari ya pili**.\
Mara moja baada ya hii **mshambuliaji anaweza kutuma nambari ya kwanza** na **gari itafungwa** (muhanga atadhani bonyeza la pili lililofunga). Kisha, mshambuliaji ataweza **kutuma nambari ya pili iliyoporwa kufungua** gari (ikiwa **nambari ya "kufunga gari" inaweza kutumika pia kufungua**). Inaweza kuhitajika mabadiliko ya masafa (kuna magari yanayotumia nambari sawa kufungua na kufunga lakini yanasikiliza amri zote kwa masafa tofauti).

Mshambuliaji anaweza **kuzuia mpokeaji wa gari na si mpokeaji wake** kwa sababu ikiwa mpokeaji wa gari anasikiliza kwa mfano 1MHz ya upana wa wigo, mshambuliaji hata **hatazuia** masafa sahihi yanayotumiwa na kifungua mbali lakini **yale karibu katika wigo huo** wakati **mpokeaji wa mshambuliaji atakuwa akisikiliza katika wigo mdogo** ambapo anaweza kusikiliza ishara ya kifungua mbali **bila ishara ya kuzuia**.

{% hint style="warning" %}
Utekelezaji mwingine unaonyesha kuwa **nambari ya kubadilika ni sehemu** ya nambari jumla iliyotumwa. Yaani nambari iliyotumwa ni **funguo wa biti 24** ambapo **12 za kwanza ni nambari za kubadilika**, **8 za pili ni amri** (kama vile kufunga au kufungua) na 4 za mwisho ni **thibitisho**. Magari yanayotekeleza aina hii pia yanaweza kuathiriwa kwa urahisi kwani mshambuliaji anahitaji tu kubadilisha sehemu ya nambari ya kubadilika ili aweze **kutumia nambari yoyote ya kubadilika kwa masafa yote mawili**.
{% endhint %}

{% hint style="danger" %}
Tambua kuwa ikiwa muhanga atatuma nambari ya tatu wakati mshambuliaji anatuma ya kwanza, nambari ya kwanza na ya pili itafutwa.
### Shambulizi la Kupiga Kelele la Kuzuia

Kujaribu dhidi ya mfumo wa nambari inayobadilika baada ya kufungwa kwenye gari, **kutuma nambari ile ile mara mbili** mara moja **ilikifanya kifaa cha kengele** na kizuizi kuanza kutoa **huduma ya kipekee ya kukataa huduma**. Kwa kushangaza, njia ya **kulemaza kifaa cha kengele** na kizuizi ilikuwa **kupiga** **kitufe cha mbali**, ikimpa mshambuliaji uwezo wa **kufanya shambulizi la kukataa huduma mara kwa mara**. Au changanya shambulizi hili na **lile la awali ili kupata nambari zaidi** kwani muathiriwa angependa kusitisha shambulizi haraka iwezekanavyo.

## Marejeo

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
