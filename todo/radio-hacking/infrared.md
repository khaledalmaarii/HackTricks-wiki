# Infrared

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Jinsi Infrared Inavyofanya Kazi <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Mwanga wa Infrared haionekani na binadamu**. Wavelength ya IR ni kutoka **0.7 hadi 1000 microns**. Vidhibiti vya nyumbani hutumia ishara ya IR kwa uhamisho wa data na hufanya kazi kwenye safu ya wavelength ya 0.75..1.4 microns. Kipokezi cha umeme kwenye kifaa hicho hufanya taa ya infrared ichanganye na kasi maalum, ikigeuza ishara ya dijiti kuwa ishara ya IR.

Kwa kupokea ishara za IR, hutumiwa **kipokezi cha picha**. Inabadilisha mwanga wa IR kuwa mihimili ya voltage, ambayo tayari ni **ishara za dijiti**. Kawaida, kuna **kipambaza nuru gizani ndani ya kipokezi**, ambacho kinapitisha **wavelength inayotakiwa tu** na kukata kelele.

### Aina za Itifaki za IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Itifaki za IR zinatofautiana katika mambo 3:

* uendeshaji wa biti
* muundo wa data
* kubeba kipimo - mara nyingi kwenye safu ya 36..38 kHz

#### Njia za uendeshaji wa biti <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Uendeshaji wa Umbali wa Mshipa**

Biti zinaendeshwa kwa kubadilisha urefu wa nafasi kati ya mshipa. Upana wa mshipa yenyewe ni thabiti.

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. Uendeshaji wa Upana wa Mshipa**

Biti zinaendeshwa kwa kubadilisha upana wa mshipa. Upana wa nafasi baada ya mshipa ni thabiti.

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. Uendeshaji wa Awamu**

Inajulikana pia kama uendeshaji wa Manchester. Thamani ya mantiki inaamuliwa na umbo la mpito kati ya mshipa na nafasi. "Nafasi hadi mshipa" inaonyesha mantiki "0", "mshipa hadi nafasi" inaonyesha mantiki "1".

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. Uunganisho wa njia za awali na nyingine za kipekee**

{% hint style="info" %}
Kuna itifaki za IR ambazo zina **jaribu kuwa za kawaida** kwa aina kadhaa za vifaa. Zinazojulikana zaidi ni RC5 na NEC. Kwa bahati mbaya, maarufu zaidi **haimaanishi ya kawaida zaidi**. Katika mazingira yangu, nilikutana na vijijisanduku viwili vya NEC na hakuna kimoja cha RC5.

Wazalishaji wanapenda kutumia itifaki zao za kipekee za IR, hata ndani ya safu ile ile ya vifaa (kwa mfano, vijisanduku vya TV). Kwa hivyo, vidhibiti kutoka kampuni tofauti na mara nyingine kutoka kwa mifano tofauti kutoka kampuni moja, haziwezi kufanya kazi na vifaa vingine vya aina ile ile.
{% endhint %}

### Kuchunguza Ishara ya IR

Njia sahihi zaidi ya kuona jinsi ishara ya IR ya kijijisanduku inavyoonekana ni kutumia oscilloscope. Haibadilishi au kugeuza ishara iliyopokelewa, inaonyeshwa "kama ilivyo". Hii ni muhimu kwa majaribio na uchunguzi. Nitaweka ishara inayotarajiwa kwa mfano wa itifaki ya NEC.

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

Kawaida, kuna kichwa cha habari mwanzoni mwa pakiti iliyohifadhiwa. Hii inaruhusu mpokeaji kubaini kiwango cha faida na mandharinyuma. Pia kuna itifaki bila kichwa cha habari, kwa mfano, Sharp.

Kisha data inatumwa. Muundo, kichwa cha habari, na njia ya uendeshaji wa biti hutegemea itifaki maalum.

**Itifaki ya NEC ya IR** ina amri fupi na nambari ya kurudia, ambayo hutumwa wakati kifungo kinasukumwa. Sifa zote mbili, amri na nambari ya kurudia, zina kichwa cha habari sawa mwanzoni.

**Amri ya NEC**, mbali na kichwa cha habari, inajumuisha bajeti ya anwani na bajeti ya nambari ya amri, ambayo kifaa kinaelewa ni nini kinahitaji kufanywa. Bajeti ya anwani na bajeti ya nambari ya amri zinadondoshwa na thamani za kinyume, ili kuhakiki uadilifu wa uhamisho. Kuna biti ya kusimamisha ziada mwishoni mwa amri.

**Nambari ya kurudia** ina "1" baada ya kichwa cha habari, ambayo ni biti ya kusimamisha.

Kwa **mantiki "0" na "1"** NEC hutumia Uendeshaji wa Umbali wa Mshipa: kwanza, mshipa unatumiwa baada ya hapo kuna kusimama, urefu wake unaweka thamani ya biti.

### Mashine za Hali ya Hewa

Tofauti na vidhibiti vingine, **mashine za hali ya hewa hazitumi tu nambari ya kifungo kilichosukumwa**. Pia **hutuma habari yote** wakati kifungo kinaposukumwa ili kuhakikisha kuwa **mashine ya hali ya hewa na kijijisanduku cha kudhibiti vimekamilishwa**.\
Hii itazuia mashine iliyowekwa kama 20ºC kuongezeka hadi 21ºC na kijijisanduku kimoja, na kisha wakati kijijisanduku kingine, ambacho bado kina joto kama 20ºC, kinatumika kuongeza joto zaidi, itaongeza joto hadi 21ºC (na sio hadi 22ºC ikidhani kuwa iko kwenye 21ºC).

### Mashambulizi

Unaweza kushambulia Infrared na Flipper Zero
