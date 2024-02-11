# Redio

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)ni chombo cha bure cha kuchambua ishara za dijiti kwa GNU/Linux na macOS, kilichoundwa kuchukua habari za ishara za redio zisizojulikana. Inasaidia vifaa vingi vya SDR kupitia SoapySDR, na inaruhusu demodulation inayoweza kurekebishwa ya ishara za FSK, PSK, na ASK, kudecode video za analogi, kuchambua ishara zenye mafuriko, na kusikiliza njia za sauti za analogi (yote kwa wakati halisi).

### Mpangilio Msingi

Baada ya kusakinisha, kuna mambo machache ambayo unaweza kuzingatia kusanidi.\
Katika mipangilio (kitufe cha kichupo cha pili) unaweza kuchagua **kifaa cha SDR** au **kuchagua faili** ya kusoma na ni kiasi gani cha kusintoniza na kiwango cha Sampuli (inapendekezwa hadi 2.56Msps ikiwa PC yako inaunga mkono)\\

![](<../../.gitbook/assets/image (655) (1).png>)

Katika tabia ya GUI, inapendekezwa kuwezesha mambo machache ikiwa PC yako inaunga mkono:

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
Ikiwa utagundua kuwa PC yako haikamati vitu, jaribu kulemaza OpenGL na kupunguza kiwango cha sampuli.
{% endhint %}

### Matumizi

* Tu **kukamata wakati fulani wa ishara na kuiyachambua** tuweke kitufe "Bonyeza kuchukua" kwa muda mrefu kama unahitaji.

![](<../../.gitbook/assets/image (631).png>)

* **Tuner** ya SigDigger inasaidia **kukamata ishara bora** (lakini inaweza pia kuzidisha). Kwa kawaida anza na 0 na endelea **kuifanya kuwa kubwa** hadi utapata **kelele** iliyowekwa ni **kubwa** kuliko **uboreshaji wa ishara** unayohitaji).

![](<../../.gitbook/assets/image (658).png>)

### Kusawazisha na kituo cha redio

Na [**SigDigger** ](https://github.com/BatchDrake/SigDigger)kusawazisha na kituo unachotaka kusikia, sanidi chaguo la "Onyesho la sauti ya msingi", sanidi upana wa bandi ili kupata habari zote zinazotumwa, na kisha weka Tuner kwenye kiwango kabla ya kelele kuanza kuongezeka kwa kweli:

![](<../../.gitbook/assets/image (389).png>)

## Mbinu za Kuvutia

* Wakati kifaa kinatuma mafuriko ya habari, kawaida **sehemu ya kwanza itakuwa ni ishara ya awali** kwa hivyo **hakuna haja** ya **kuwa na wasiwasi** ikiwa **hautapata habari** au ikiwa kuna **makosa fulani** hapo.
* Katika fremu za habari, kawaida unapaswa **kupata fremu tofauti zilizolingana vizuri kati yao**:

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **Baada ya kupata bits unaweza kuhitaji kuziprocess kwa njia fulani**. Kwa mfano, katika ucodishaji wa Manchester, up+chini utakuwa 1 au 0 na chini+juu utakuwa mwingine. Kwa hivyo jozi za 1s na 0s (juu na chini) zitakuwa 1 halisi au 0 halisi.
* Hata ikiwa ishara inatumia ucodishaji wa Manchester (haiwezekani kupata zaidi ya 0s au 1s mbili mfululizo), unaweza **kupata 1s au 0s kadhaa pamoja katika ishara ya awali**!

### Kufunua aina ya modulisheni na IQ

Kuna njia 3 za kuhifadhi habari katika ishara: Kwa kubadilisha **amplitude**, **frequency** au **phase**.\
Ikiwa unachunguza ishara kuna njia tofauti za kujaribu kugundua ni nini kinatumika kuhifadhi habari (pata njia zaidi hapa chini) lakini moja nzuri ni kuangalia grafu ya IQ.

![](<../../.gitbook/assets/image (630).png>)

* **Kugundua AM**: Ikiwa kwenye grafu ya IQ inaonekana kwa mfano **mduara 2** (labda mmoja kwenye 0 na mwingine kwenye amplitude tofauti), inaweza maana kuwa hii ni ishara ya AM. Hii ni kwa sababu kwenye grafu ya IQ umbali kati ya 0 na mduara ni amplitude ya ishara, kwa hivyo ni rahisi kuona amplitudes tofauti zikitumiwa.
* **Kugundua PM**: Kama kwenye picha iliyotangulia, ikiwa utapata mduara mdogo usiohusiana kati yao inamaanisha kuwa hutumiwi modulisheni ya awamu. Hii ni kwa sababu kwenye grafu ya IQ, pembe kati ya alama na 0,0 ni awamu ya ishara, kwa hivyo hii inamaanisha kuwa hutumiwi awamu 4 tofauti.
* Tafadhali kumbuka kuwa ikiwa habari imefichwa katika ukweli kwamba awamu imebadilika na sio katika awamu yenyewe, hautaona awamu tofauti zikiwa wazi wazi.
* **Kugundua FM**: IQ haina uga wa kutambua masafa (umbali na kitovu ni amplitude na pembe ni awamu).\
Kwa hivyo, ili kutambua FM, unapaswa **kuona kimsingi mduara tu** kwenye grafu hii.\
Zaidi ya hayo, masafa tofauti "yanawakilishwa" na grafu ya IQ na **kasi ya kuongezeka kwa mzunguko** (kwa hivyo katika SysDigger kuchagua ishara grafu ya IQ inajazwa, ikiwa utapata kasi ya kuongezeka au mabadiliko ya mwelekeo kwenye mduara ulioundwa inaweza maana kuwa hii ni FM):

## Mfano wa AM

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Kufunua AM

#### Kuchunguza kifuniko

Kuchunguza habari ya AM na [**SigDigger**
#### Pamoja na IQ

Katika mfano huu unaweza kuona jinsi kuna **duara kubwa** lakini pia **idadi kubwa ya alama katikati**.

![](<../../.gitbook/assets/image (640).png>)

### Pata Kiwango cha Ishara

#### Kwa ishara moja

Chagua ishara ndogo unayoweza kupata (ili uwe na uhakika ni moja tu) na angalia "Selection freq". Katika kesi hii itakuwa 1.013kHz (kwa hivyo 1kHz).

![](<../../.gitbook/assets/image (638) (1).png>)

#### Kwa kikundi cha ishara

Unaweza pia kuonyesha idadi ya ishara utakazochagua na SigDigger itahesabu kiwango cha ishara 1 (kuchagua ishara nyingi zaidi labda ni bora zaidi). Katika kesi hii, nilichagua ishara 10 na "Selection freq" ni 1.004 Khz:

![](<../../.gitbook/assets/image (635).png>)

### Pata Bits

Baada ya kugundua kuwa hii ni ishara iliyobadilishwa **AM** na **kiwango cha ishara** (na kujua kuwa katika kesi hii kitu kilichoinuka kinamaanisha 1 na kitu kilichoshuka kinamaanisha 0), ni rahisi sana **kupata bits** zilizoandikwa kwenye ishara. Kwa hivyo, chagua ishara na habari na sanidi sampuli na uamuzi na bonyeza sampuli (hakikisha **Amplitude** imechaguliwa, kiwango cha ishara kilichogunduliwa kimehakikishiwa, na **Gadner clock recovery** imechaguliwa):

![](<../../.gitbook/assets/image (642) (1).png>)

* **Sync to selection intervals** inamaanisha kuwa ikiwa hapo awali ulichagua vipindi ili kupata kiwango cha ishara, kiwango hicho cha ishara kitatumika.
* **Manual** inamaanisha kuwa kiwango cha ishara kilichoonyeshwa kitatumika
* Katika **Fixed interval selection** unaweka idadi ya vipindi ambavyo vinapaswa kuchaguliwa na inahesabu kiwango cha ishara kutoka hapo
* **Gadner clock recovery** kawaida ni chaguo bora, lakini bado unahitaji kuonyesha kiwango cha ishara takriban.

Kwa kubonyeza sampuli, hii inaonekana:

![](<../../.gitbook/assets/image (659).png>)

Sasa, ili SigDigger ielewe **eneo** la kiwango cha kubeba habari, unahitaji bonyeza **kiwango cha chini** na kubaki bonyeza hadi kiwango kikubwa:

![](<../../.gitbook/assets/image (662) (1) (1) (1).png>)

Ikiwa kungekuwa na mfano **4 tofauti za viwango vya amplitude**, ungehitaji kuweka **Bits per symbol kuwa 2** na kuchagua kutoka kwa ndogo hadi kubwa.

Hatimaye, **kuongeza** **Zoom** na **kubadilisha Ukubwa wa safu** unaweza kuona bits (na unaweza kuchagua yote na kunakili ili kupata bits zote):

![](<../../.gitbook/assets/image (649) (1).png>)

Ikiwa ishara ina zaidi ya biti 1 kwa ishara (kwa mfano 2), SigDigger hana njia ya kujua ni ishara ipi ni 00, 01, 10, 11, kwa hivyo itatumia **rangi za kijivu tofauti** kuwakilisha kila moja (na ikiwa unakili bits itatumia **nambari kutoka 0 hadi 3**, utahitaji kuzitendea).

Pia, tumia **nambari** kama vile **Manchester**, na **juu+chini** inaweza kuwa **1 au 0** na chini+juu inaweza kuwa 1 au 0. Katika kesi hizo, unahitaji **kutendea juu (1) na chini (0)** ulizopata ili kubadilisha jozi za 01 au 10 kama 0 au 1.

## Mfano wa FM

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Kufunua FM

#### Kuchunguza masafa na waveform

Mfano wa ishara inayotuma habari iliyobadilishwa kwa FM:

![](<../../.gitbook/assets/image (661) (1).png>)

Katika picha iliyotangulia unaweza kuona wazi kuwa **masafa 2 yanatumika** lakini ikiwa **unaangalia** **waveform** huenda **usiweze kutambua kwa usahihi masafa 2 tofauti**:

![](<../../.gitbook/assets/image (653).png>)

Hii ni kwa sababu nimechukua ishara katika masafa yote mawili, kwa hivyo moja ni karibu na nyingine kwa upande hasi:

![](<../../.gitbook/assets/image (656).png>)

Ikiwa masafa yaliyosawazishwa yako **karibu zaidi na masafa moja kuliko mengine**, unaweza kuona kwa urahisi masafa 2 tofauti:

![](<../../.gitbook/assets/image (648) (1) (1) (1).png>)

![](<../../.gitbook/assets/image (634).png>)

#### Kuchunguza histogramu

Kwa kuchunguza histogramu ya masafa ya ishara na habari unaweza kuona kwa urahisi ishara 2 tofauti:

![](<../../.gitbook/assets/image (657).png>)

Katika kesi hii, ikiangalia **Histogramu ya Amplitude** utapata **amplitude moja tu**, kwa hivyo **haiwezi kuwa AM** (ikiwa unapata amplitudes nyingi inaweza kuwa kwa sababu ishara imepoteza nguvu kwenye njia):

![](<../../.gitbook/assets/image (646).png>)

Na hii itakuwa histogramu ya awamu (ambayo inafanya iwe wazi sana kuwa ishara haijabadilishwa kwa awamu):

![](<../../.gitbook/assets/image (201) (2).png>)

#### Pamoja na IQ

IQ haina uga wa kutambua masafa (umbali na kitovu ni amplitude na pembe ni awamu).\
Kwa hivyo, ili kutambua FM, unapaswa **kuona kimsingi duara** katika grafu hii.\
Zaidi ya hayo, masafa tofauti "yanawakilishwa" na grafu ya IQ kwa **kasi ya kuongezeka kwa kasi kwenye duara** (kwa hivyo katika SysDigger kuchagua ishara grafu ya IQ inajazwa, ikiwa unapata kasi ya kuongezeka kwa kasi au mabadiliko ya mwelekeo kwenye duara iliyoundwa inaweza kuwa inamaanisha kuwa hii ni FM):

![](<../../.gitbook/assets/image (643) (1).png>)

### Pata Kiwango cha Ishara

Unaweza kutumia **njia ile ile kama ile iliyotumiwa katika mfano wa AM** kupata kiwango cha ishara mara tu utakapogundua masafa yanayobeba ishara.

### Pata Bits

Unaweza kutumia **njia ile ile kama ile iliyotumiwa katika mfano wa AM** kupata bits mara tu utakapogundua kuwa ishara imebadilishwa kwa masafa na kiwango cha ishara.
