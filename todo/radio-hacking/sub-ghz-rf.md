# Sub-GHz RF

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Milango ya Gari

Wafunguo wa milango ya gari kwa kawaida hufanya kazi kwenye masafa ya 300-190 MHz, na masafa yanayotumiwa zaidi ni 300 MHz, 310 MHz, 315 MHz, na 390 MHz. Kisafa hiki kinatumika kwa kawaida kwa wafunguo wa milango ya gari kwa sababu ni kidogo sana kuliko masafa mengine na ni nadra kupata kuingiliana na vifaa vingine.

## Milango ya Gari

Wafunguo wengi wa gari hufanya kazi kwenye **315 MHz au 433 MHz**. Hizi ni masafa ya redio, na hutumiwa katika matumizi mbalimbali. Tofauti kuu kati ya masafa haya mawili ni kwamba 433 MHz ina mbali zaidi kuliko 315 MHz. Hii inamaanisha kuwa 433 MHz ni bora kwa matumizi yanayohitaji mbali kubwa, kama vile kuingia kwa mbali bila funguo.\
Ulaya hutumia 433.92MHz kwa kawaida na Marekani na Japani hutumia 315MHz.

## **Shambulio la Brute-force**

<figure><img src="../../.gitbook/assets/image (1084).png" alt=""><figcaption></figcaption></figure>

Badala ya kutuma kila nambari mara 5 (kutumwa hivi ili kuhakikisha mpokeaji anapata) basi itume mara moja, muda unapunguzwa hadi dakika 6:

<figure><img src="../../.gitbook/assets/image (622).png" alt=""><figcaption></figcaption></figure>

na ikiwa **ondoa kipindi cha kusubiri cha 2 ms** kati ya ishara unaweza **kupunguza muda hadi dakika 3.**

Zaidi, kwa kutumia Mfululizo wa De Bruijn (njia ya kupunguza idadi ya bits inayohitajika kutuma nambari zote za binary zinazowezekana kwa kudukua) huu **muda unapunguzwa hadi sekunde 8 tu**:

<figure><img src="../../.gitbook/assets/image (583).png" alt=""><figcaption></figcaption></figure>

Mfano wa shambulio hili ulitekelezwa katika [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Kuhitaji **kielelezo kitazuia Mfululizo wa De Bruijn** na **nambari za kugeuka zitazuia shambulio hili** (ikiwa nambari ni ndefu vya kutosha kutosha kudukuliwa).

## Shambulio la Sub-GHz

Kudukua ishara hizi na Flipper Zero angalia:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Ulinzi wa Nambari za Kugeuka

Wafunguo wa milango ya gari ya moja kwa moja kwa kawaida hutumia kudhibiti mbali wa redio ili kufungua na kufunga mlango wa gari. Kudhibiti mbali **hutuma ishara ya masafa ya redio (RF)** kwa kifungua mlango wa gari, ambacho huchochea injini kufungua au kufunga mlango.

Inawezekana kwa mtu kutumia kifaa kinachoitwa kuchukua nambari kudaka ishara ya RF na kuirekodi kwa matumizi baadaye. Hii inajulikana kama **shambulio la kurudia**. Ili kuzuia aina hii ya shambulio, wafunguo wengi wa milango ya gari ya kisasa hutumia njia ya usimbaji salama zaidi inayoitwa mfumo wa **nambari za kugeuka**.

**Ishara ya RF kwa kawaida hutumwa kwa kutumia nambari za kugeuka**, maana yake ni kwamba nambari inabadilika kila inapotumiwa. Hii inafanya iwe **ngumu** kwa mtu yeyote kuchukua **ishara** na kuitumia kupata **upatikanaji usiohalali** wa gari.

Katika mfumo wa nambari za kugeuka, kudhibiti mbali na kifungua mlango wa gari wana **algoritimu inayoshirikiana** ambayo **inazalisha nambari mpya** kila wakati kifungua mbali kinapotumiwa. Kifungua mlango wa gari kitajibu tu kwa **nambari sahihi**, hivyo kufanya iwe ngumu zaidi kwa mtu kupata upatikanaji usiohalali wa gari kwa kuchukua nambari.

### **Shambulio la Kiungo Kilichopotea**

Kimsingi, unasikiliza kifungo na **kuchukua ishara wakati kifungua mbali iko nje ya mbali** ya kifaa (semaje gari au garaji). Kisha unahamia kwenye kifaa na **kutumia nambari uliyochukua kufungua**.

### Shambulio la Kuzuia Kiungo Kamili

Mshambuliaji anaweza **kuzuia ishara karibu na gari au mpokeaji** ili **mpokeaji asisikie kweli nambari**, na mara tu hilo linapotokea unaweza tu **kuchukua na kurudia** nambari unapomaliza kuzuia.

Mkosa atafikia wakati fulani atatumia **funguo kufunga gari**, lakini basi shambulio litakuwa **limeirekodi "nambari za kufunga" za kutosha** ambazo kwa matumaini zinaweza kutumwa tena kufungua mlango (inaweza kuhitajika **mabadiliko ya masafa** kwani kuna magari yanayotumia nambari sawa kufungua na kufunga lakini yanasikiliza amri zote kwa masafa tofauti).

{% hint style="warning" %}
**Kuzuia kazi**, lakini inaonekana kama kama **mtu anayefunga gari anajaribu tu milango** kuhakikisha wamefungwa wangeweza kugundua gari halijafungwa. Aidha, kama wangekuwa na ufahamu wa mashambulizi kama hayo wangeweza hata kusikiliza ukweli kwamba milango haikufanya sauti ya kufunga **au taa za gari** hazikutoa ishara wakati walipobonyeza kitufe cha ‘funga’.
{% endhint %}

### **Shambulio la Kuchukua Nambari (inayoitwa ‘RollJam’)**

Hii ni mbinu ya **Kuzuia ya siri zaidi**. Mshambuliaji atazuia ishara, hivyo wakati mkosa anajaribu kufunga mlango haitafanya kazi, lakini mshambuliaji atakapo **irekodi nambari hii**. Kisha, mkosa atajaribu kufunga gari tena kwa kubonyeza kitufe na gari ita **irekodi nambari ya pili**.\
Mara moja baada ya hii **mshambuliaji anaweza kutuma nambari ya kwanza** na **gari itafunga** (mkosa atadhani bonyeza la pili lililofunga). Kisha, mshambuliaji ataweza **kutuma nambari ya pili iliyoporwa kufungua** gari (ikiwa inawezekana kwamba **nambari ya "kufunga gari" inaweza kutumika pia kufungua**). Mabadiliko ya masafa yanaweza kuhitajika (kuna magari yanayotumia nambari sawa kufungua na kufunga lakini yanasikiliza amri zote kwa masafa tofauti).

Mshambuliaji anaweza **kuzuia mpokeaji wa gari na sio mpokeaji wake** kwa sababu ikiwa mpokeaji wa gari anasikiliza kwa mfano 1MHz ya upana wa wigo, mshambuliaji hata **hatazuia** masafa sahihi yanayotumiwa na kifungua mbali lakini **moja karibu katika wigo huo** wakati **mpokeaji wa mshambuliaji atakuwa akisikiliza kwa wigo mdogo** ambapo anaweza kusikiliza ishara ya kifungua mbali **bila ishara ya kuzuia**.

{% hint style="warning" %}
Utekelezaji mwingine unaonekana katika maelezo ya kiufundi unaonyesha kuwa **nambari ya kugeuka ni sehemu** ya nambari jumla iliyotumwa. Yaani nambari iliyotumwa ni **funguo ya biti 24** ambapo **12 za kwanza ni nambari ya kugeuka**, **8 za pili ni amri** (kama vile kufunga au kufungua) na 4 za mwisho ni **thibitisho**. Magari yanayotekeleza aina hii pia yanaweza kuathiriwa kwa urahisi kwani mshambuliaji anahitaji tu kubadilisha sehemu ya nambari ya kugeuka ili aweze **kutumia nambari yoyote ya kugeuka kwa masafa yote mawili**.
{% endhint %}

{% hint style="danger" %}
Tafadhali kumbuka kuwa ikiwa mkosa atatuma nambari ya tatu wakati mshambuliaji anatuma ya kwanza, nambari ya kwanza na ya pili itafutwa.
### Shambulio la Kupiga Kelele la Alarm

Kujaribu dhidi ya mfumo wa nambari inayobadilika baada ya kufungwa kwenye gari, **kutuma nambari ile ile mara mbili** mara moja **ilizidisha alarm** na kifungo cha gari kutoa fursa ya **kipekee ya kukataa huduma**. Kwa kushangaza njia ya **kulemaza alarm** na kifungo cha gari ilikuwa **kupiga** **kidhibiti cha mbali**, ikimpa mshambuliaji uwezo wa **kutekeleza shambulio la kukataa huduma mara kwa mara**. Au changanya shambulio hili na **lile la awali ili kupata nambari zaidi** kwani muathiriwa angependa kusitisha shambulio haraka iwezekanavyo.

## Marejeo

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
