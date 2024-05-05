# Mionzi

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Jinsi Mionzi Inavyofanya Kazi <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Mionzi ya Infrared haionekani kwa binadamu**. Wavuti ya IR ni kutoka **0.7 hadi 1000 mikroni**. Vidhibiti vya nyumbani hutumia ishara ya IR kwa uhamisho wa data na hufanya kazi katika safu ya wavuti ya 0.75..1.4 mikroni. Kwenye kifaa cha kudhibiti cha mbali, kuna kipokeaji wa picha kinachotumika. **Hugeuza mwanga wa IR kuwa mapigo ya voltage**, ambayo tayari ni **ishara za dijiti**. Kawaida, kuna **kipokeaji wa nuru ya giza ndani ya kipokeaji**, ambayo inaruhusu **wavuti inayotakiwa tu kupitia** na kuzuia kelele.

### Aina za Itifaki za IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Itifaki za IR hutofautiana katika mambo 3:

* uendeshaji wa biti
* muundo wa data
* kubeba mara kwa mara — mara nyingi katika safu ya 36..38 kHz

#### Njia za uendeshaji wa biti <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Uendeshaji wa Umbali wa Pigo**

Biti zinaendeshwa kwa kubadilisha urefu wa nafasi kati ya mapigo. Upana wa pigo lenyewe ni thabiti.

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Uendeshaji wa Upana wa Pigo**

Biti zinaendeshwa kwa kubadilisha upana wa pigo. Upana wa nafasi baada ya mlipuko wa pigo ni thabiti.

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Uendeshaji wa Fungu la Pigo**

Pia inajulikana kama uendeshaji wa Manchester. Thamani ya mantiki inadefinishwa na polariti ya mpito kati ya mlipuko wa pigo na nafasi. "Nafasi kwenda mlipuko wa pigo" inaashiria mantiki "0", "mlipuko wa pigo kwenda nafasi" inaashiria mantiki "1".

<figure><img src="../../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Mchanganyiko wa zile za awali na nyingine za kipekee**

{% hint style="info" %}
Kuna itifaki za IR ambazo zina **jaribu kuwa za kipekee** kwa aina kadhaa za vifaa. Zile maarufu zaidi ni RC5 na NEC. Kwa bahati mbaya, zile maarufu zaidi **haimaanishi kuwa ni za kawaida**. Katika mazingira yangu, nilikutana na vidhibiti viwili vya NEC tu na hakuna cha RC5.

Watengenezaji wanapenda kutumia itifaki zao za IR za kipekee, hata ndani ya safu ile ile ya vifaa (kwa mfano, TV-boxes). Kwa hivyo, vidhibiti kutoka kampuni tofauti na mara nyingine kutoka kwa mifano tofauti kutoka kampuni moja, haziwezi kufanya kazi na vifaa vingine vya aina hiyo.
{% endhint %}

### Kuchunguza Ishara ya IR

Njia bora zaidi ya kuona jinsi ishara ya IR ya kifaa cha mbali inavyoonekana ni kutumia oscilloscope. Haifanyi demodulate au kubadilisha ishara iliyopokelewa, inaonyeshwa "kama ilivyo". Hii ni muhimu kwa majaribio na kutatua matatizo. Nitaelezea ishara inayotarajiwa kwa mfano wa itifaki ya NEC.

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

Kawaida, kuna kichwa cha habari mwanzoni mwa pakiti iliyohifadhiwa. Hii inaruhusu mpokeaji kujua kiwango cha faida na mandharinyuma. Pia kuna itifaki bila kichwa cha habari, kwa mfano, Sharp.

Kisha data inatumwa. Muundo, kichwa cha habari, na njia ya uendeshaji wa biti inaamuliwa na itifaki maalum.

Itifaki ya **NEC IR** ina amri fupi na msimbo wa kurudia, ambao hutumwa wakati kifungo kinasukumwa. Ili kuhakikisha usahihi wa uhamisho, amri na msimbo wa kurudia una kichwa cha habari sawa mwanzoni.

**Amri ya NEC**, mbali na kichwa cha habari, inajumuisha baiti ya anwani na baiti ya nambari ya amri, ambayo kifaa huelewa ni nini kinapaswa kufanywa. Baiti za anwani na nambari ya amri zinadaiwa na thamani za kinyume, kuthibitisha usahihi wa uhamisho. Kuna biti ya kusimamisha ya ziada mwishoni mwa amri.

**Msimbo wa kurudia** una "1" baada ya kichwa cha habari, ambayo ni biti ya kusimamisha.

Kwa **mantiki "0" na "1"** NEC hutumia Uendeshaji wa Umbali wa Pigo: kwanza, mlipuko wa pigo unatumwa kisha kuna kusitisha, urefu wake unaweka thamani ya biti.

### Mashine za Hewa

Tofauti na vidhibiti vingine, **mashine za hewa hazitumi tu nambari ya kifungo kilichosukumwa**. Pia **hutuma habari yote** wakati kifungo kinasukumwa ili kuhakikisha kuwa **mashine ya hewa na kifaa cha mbali vinafanana**. Hii itazuia kwamba mashine iliyowekwa kama 20ºC iongezwe hadi 21ºC na kisha wakati kifaa kingine cha mbali, ambacho bado kina joto kama 20ºC, kinatumika kuongeza joto zaidi, ita "ongeza" hadi 21ºC (na sio 22ºC ikifikiria kuwa iko 21ºC).

### Mashambulizi

Unaweza kushambulia Mionzi ya Infrared na Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Marejeo

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)
