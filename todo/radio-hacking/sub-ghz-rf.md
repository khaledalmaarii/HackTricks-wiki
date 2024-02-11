# Sub-GHz RF

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Milango ya Gari

Wafunguo wa milango ya gari kawaida hufanya kazi kwa masafa katika kiwango cha 300-190 MHz, na masafa yanayotumiwa sana ni 300 MHz, 310 MHz, 315 MHz, na 390 MHz. Kiwango hiki cha masafa kinatumiwa kawaida kwa wafunguo wa milango ya gari kwa sababu kina msongamano mdogo kuliko bendi zingine za masafa na ni kidogo uwezekano wa kupata kuingiliwa na vifaa vingine.

## Milango ya Gari

Wafunguo wengi wa gari hufanya kazi kwa masafa ya **315 MHz au 433 MHz**. Hizi ni masafa ya redio, na hutumiwa katika matumizi mbalimbali tofauti. Tofauti kuu kati ya masafa haya mawili ni kwamba 433 MHz ina mbalimbali kubwa kuliko 315 MHz. Hii inamaanisha kuwa 433 MHz ni bora kwa matumizi yanayohitaji mbalimbali kubwa, kama vile kuingia kwa kijijini bila ufunguo.\
Barani Ulaya, 433.92MHz hutumiwa kawaida na katika Marekani na Japani ni 315MHz.

## **Shambulio la Brute-force**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

Badala ya kutuma kila nambari mara 5 (kutumwa kwa njia hii ili kuhakikisha mpokeaji anapokea), unaweza kuituma mara moja, wakati unapunguzwa hadi dakika 6:

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

Na ikiwa **ondoa kipindi cha kusubiri cha 2 ms** kati ya ishara, unaweza **kupunguza wakati hadi dakika 3**.

Zaidi ya hayo, kwa kutumia De Bruijn Sequence (njia ya kupunguza idadi ya bits inayohitajika kutuma nambari zote za binary zinazowezekana kwa nguvu), **wakati huu unapunguzwa hadi sekunde 8**:

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

Mfano wa shambulio hili ulitekelezwa katika [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Kuweka **kielelezo kutazuia De Bruijn Sequence** optimization na **codes za kusonga zitazuia shambulio hili** (ikiwa nambari ni ndefu ya kutosha ili isidukuliwe kwa nguvu).

## Shambulio la Sub-GHz

Kuwashambulia ishara hizi na Flipper Zero angalia:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Ulinzi wa Codes za Kusonga

Wafunguo wa milango ya gari ya kiotomatiki kawaida hutumia kijijini cha udhibiti wa wireless kufungua na kufunga mlango wa gari. Kijijini cha udhibiti **hutuma ishara ya masafa ya redio (RF)** kwa mfunguo wa mlango wa gari, ambayo inawezesha injini kufungua au kufunga mlango.

Inawezekana kwa mtu kutumia kifaa kinachojulikana kama code grabber kuiba ishara ya RF na kuihifadhi kwa matumizi ya baadaye. Hii inajulikana kama **shambulio la kurudia**. Ili kuzuia aina hii ya shambulio, wafunguo wengi wa milango ya gari ya kisasa hutumia njia ya usimbaji salama zaidi inayojulikana kama **mfumo wa codes za kusonga**.

**Ishara ya RF kawaida hutumwa kwa kutumia code za kusonga**, ambayo inamaanisha kuwa code inabadilika kila wakati inapotumiwa. Hii inafanya iwe **ngumu** kwa mtu yeyote kudaka ishara na kuitumia kupata ufikiaji **usiohalali** kwenye gari.

Katika mfumo wa codes za kusonga, kijijini cha udhibiti na mfunguo wa mlango wa gari wana **algorithmu inayoshiriki** ambayo **inazalisha code mpya** kila wakati kijijini kinapotumiwa. Mfunguo wa mlango wa gari utajibu tu kwa **code sahihi**, hivyo inakuwa ngumu zaidi kwa mtu yeyote kupata ufikiaji usiohalali kwenye gari kwa kudaka tu code.

### **Shambulio la Kiungo Kilichopotea**

Kimsingi, unalisikiliza kifungo na **kudaka ishara wakati kijijini kiko nje ya upeo** wa kifaa (kama gari au garaji). Kisha, unahamia kwenye kifaa na **kutumia code uliyodaka kufungua**.

### Shambulio la Kuzuia Kiungo Kamili

Mshambuliaji anaweza **kuzuia ishara karibu na gari au mpokeaji** ili **mpokeaji asisikie kwa kweli code**, na mara tu hilo linapotokea, unaweza tu **kudaka na kucheza tena** code wakati umesimamisha kuzuia.

Mwathirika wakati fulani atatumia **funguo kufunga gari**, lakini kisha shambulio litakuwa lime**hifadhiwa codes za "funga mlango"** za kutosha ambazo kwa matumaini zinaweza kutumwa tena kufungua mlango (inaweza kuhitajika **mabadiliko ya masafa** kwani kuna magari yanayotumia codes sawa kufungua na kufunga lakini hulisikiliza amri zote kwa masafa tofauti).

{% hint style="warning" %}
**Kuzuia kazi**, lakini inaonekana kama ikiwa **mtu anayefunga gari anajaribu tu milango** kuhakikisha kuwa wamefungwa wangeona gari limefunguliwa. Aidha, ikiwa wangekuwa na ufahamu wa mashambulio kama hayo, wangeweza hata kusikiliza ukweli kwamba milango haikufanya sauti ya **kufunga** au taa za gari hazikung'aa wakati walipogusa kitufe cha 'funga'.
{% endhint %}

### **Shambulio la
### Shambulio la Kuzuia Kengele Inayolia

Kujaribu dhidi ya mfumo wa nambari ya kusonga baada ya kufungwa kwenye gari, **kutuma nambari ile ile mara mbili** mara moja **ilizindua kengele** na kifungo cha kuwezesha kutoa fursa ya **kukataa huduma** ya kipekee. Kwa kushangaza, njia ya **kulemaza kengele** na kifungo cha kuwezesha ilikuwa **kubonyeza** **kidhibiti cha mbali**, ikimpa mshambuliaji uwezo wa **kutekeleza shambulio la kukataa huduma kwa muda mrefu**. Au changanya shambulio hili na **lile la awali ili kupata nambari zaidi** kwani muathirika angependa kusitisha shambulio haraka iwezekanavyo.

## Marejeo

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
