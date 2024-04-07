# Redio

<details>

<summary><strong>Jifunze kuhack AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalamu wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)ni mtambulishaji wa ishara ya dijiti huru kwa GNU/Linux na macOS, iliyoundwa kutoa habari za ishara za redio zisizojulikana. Inasaidia aina mbalimbali za vifaa vya SDR kupitia SoapySDR, na inaruhusu demodulation inayoweza kurekebishwa ya ishara za FSK, PSK na ASK, kudecode video ya analog, kuchambua ishara za kuburuzika na kusikiliza njia za sauti za analog (yote kwa wakati halisi).

### Usanidi wa Msingi

Baada ya kusakinisha kuna mambo machache ambayo unaweza kuzingatia kusanidi.\
Katika mipangilio (kitufe cha tab ya pili) unaweza kuchagua **kifaa cha SDR** au **chagua faili** kusoma na ni frekwensi gani ya kusintoniza na kiwango cha Sampuli (kinapendekezwa hadi 2.56Msps ikiwa PC yako inaunga mkono)\\

![](<../../.gitbook/assets/image (242).png>)

Katika tabia ya GUI inapendekezwa kuwezesha mambo machache ikiwa PC yako inaunga mkono:

![](<../../.gitbook/assets/image (469).png>)

{% hint style="info" %}
Ikiwa unagundua kuwa PC yako haichukui vitu jaribu kulemaza OpenGL na kupunguza kiwango cha sampuli.
{% endhint %}

### Matumizi

* Tu kwa **kukamata wakati fulani wa ishara na kuanaliza** tuhifadhi kitufe "Bonyeza kuchukua" kwa muda mrefu unahitaji.

![](<../../.gitbook/assets/image (957).png>)

* **Mtatuzi** wa SigDigger husaidia **kukamata ishara bora** (lakini inaweza pia kuziharibu). Kimsingi anza na 0 na endelea **kuifanya iwe kubwa mpaka** utapata **kelele** inayoongezeka ni **kubwa** kuliko **kuboresha ishara** unayohitaji).

![](<../../.gitbook/assets/image (1096).png>)

### Kusawazisha na kituo cha redio

Pamoja na [**SigDigger** ](https://github.com/BatchDrake/SigDigger)kusawazisha na kituo unachotaka kusikia, sanidi chaguo la "Onyesho la sauti ya msingi", sanidi upana wa kupata habari zote zinazotumwa na kisha weka Mtunza kwenye kiwango kabla kelele haijaanza kuongezeka kweli:

![](<../../.gitbook/assets/image (582).png>)

## Mbinu za Kuvutia

* Wakati kifaa kinatuma mafuriko ya habari, kawaida **sehemu ya kwanza itakuwa preamble** hivyo **usihitaji** kuhangaika ikiwa **hautapata habari** au ikiwa kuna makosa fulani huko.
* Katika fremu za habari kawaida unapaswa **kupata fremu tofauti zilizo sawa kati yao**:

![](<../../.gitbook/assets/image (1073).png>)

![](<../../.gitbook/assets/image (594).png>)

* **Baada ya kupata bits unaweza kuhitaji kuziprocess kwa njia fulani**. Kwa mfano, katika ucodishaji wa Manchester up+chini itakuwa 1 au 0 na chini+juu itakuwa nyingine. Kwa hivyo jozi za 1s na 0s (juu na chini) zitakuwa 1 halisi au 0 halisi.
* Hata kama ishara inatumia ucodishaji wa Manchester (haiwezekani kupata zaidi ya 0s au 1s mbili mfululizo), unaweza **kupata 1s au 0s kadhaa pamoja katika preamble**!

### Kufunua aina ya modulisheni na IQ

Kuna njia 3 za kuhifadhi habari katika ishara: Kupitia **amplitude**, **frekwensi** au **phase**.\
Ikiwa unachunguza ishara kuna njia tofauti za kujaribu kugundua ni nini kinatumika kuhifadhi habari (pata njia zaidi hapa chini) lakini moja nzuri ni kuangalia grafu ya IQ.

![](<../../.gitbook/assets/image (785).png>)

* **Kugundua AM**: Ikiwa kwenye grafu ya IQ inaonekana kwa mfano **mduara 2** (labda moja katika 0 na nyingine katika amplitude tofauti), inaweza maana kuwa hii ni ishara ya AM. Hii ni kwa sababu kwenye grafu ya IQ umbali kati ya 0 na mduara ni amplitude ya ishara, hivyo ni rahisi kuona amplitudes tofauti zikitumiwa.
* **Kugundua PM**: Kama katika picha iliyotangulia, ikiwa unapata mduara mdogo usiohusiana kati yao inamaanisha kwamba modulisheni ya phase inatumika. Hii ni kwa sababu kwenye grafu ya IQ, pembe kati ya alama na 0,0 ni phase ya ishara, hivyo hilo lina maana kwamba matumizi ya 4 tofauti ya phase yanatumika.
* Kumbuka kwamba ikiwa habari inafichwa katika ukweli kwamba phase imebadilishwa na sio katika phase yenyewe, hutaweza kuona phases tofauti waziwazi.
* **Kugundua FM**: IQ haina uga wa kutambua frekwensi (umbali hadi katikati ni amplitude na pembe ni phase).\
Kwa hivyo, kutambua FM, unapaswa **kuona msingi wa mduara tu** katika grafu hii.\
Zaidi ya hayo, frekwensi tofauti "inawakilishwa" na grafu ya IQ kwa **kasi ya kuongezeka kote kwenye mduara** (hivyo katika SysDigger kuchagua ishara grafu ya IQ inajazwa, ikiwa unapata kasi ya kuongezeka au mabadiliko ya mwelekeo katika mduara ulioundwa inaweza maana kuwa hii ni FM):

## Mfano wa AM

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Kufunua AM

#### Kukagua konvolo

Kukagua habari ya AM na [**SigDigger** ](https://github.com/BatchDrake/SigDigger)na kuangalia **konvolo** unaweza kuona viwango tofauti vya amplitude wazi. Ishara inayotumiwa inatuma mapigo na habari katika AM, hivi ndivyo mapigo moja yanavyoonekana:

![](<../../.gitbook/assets/image (587).png>)

Na hivi ndivyo sehemu ya ishara inavyoonekana na waveform:

![](<../../.gitbook/assets/image (731).png>)

#### Kukagua Histogram

Unaweza **kuchagua ishara nzima** ambapo habari inapatikana, chagua mode ya **Amplitude** na **Uchaguzi** na bonyeza **Histogram.** Unaweza kuona kwamba viwango 2 wazi tu vinapatikana

![](<../../.gitbook/assets/image (261).png>)

Kwa mfano, ikiwa unachagua Frekwensi badala ya Amplitude katika ishara hii ya AM utapata frekwensi 1 tu (hakuna njia habari iliyomoduliwa kwa frekwensi inatumia frekwensi 1 tu).

![](<../../.gitbook/assets/image (729).png>)

Ikiwa unapata idadi kubwa ya frekwensi, huenda hii sio FM, labda frekwensi ya ishara ilibadilishwa tu kwa sababu ya channel.
#### Na IQ

Katika mfano huu unaweza kuona jinsi kuna **mduara mkubwa** lakini pia **pembezoni kuna** **pia idadi kubwa ya alama.**

![](<../../.gitbook/assets/image (219).png>)

### Pata Kiwango cha Ishara

#### Kwa ishara moja

Chagua ishara ndogo unayoweza kupata (ili uhakikishe ni moja tu) na angalia "Selection freq". Kwa mfano huu itakuwa 1.013kHz (hivyo 1kHz).

![](<../../.gitbook/assets/image (75).png>)

#### Kwa kikundi cha ishara

Unaweza pia kuonyesha idadi ya ishara utakazochagua na SigDigger itahesabu frekwensi ya ishara 1 (kuchagua ishara nyingi kunaweza kuwa bora zaidi). Katika kesi hii nilichagua ishara 10 na "Selection freq" ni 1.004 Khz:

![](<../../.gitbook/assets/image (1005).png>)

### Pata Bits

Baada ya kugundua hii ni ishara iliyopitishwa **AM** na **kiwango cha ishara** (na kujua kuwa katika kesi hii kitu kilichoinuka inamaanisha 1 na kitu kilichoshuka inamaanisha 0), ni rahisi sana **kupata bits** zilizoandikwa kwenye ishara. Kwa hivyo, chagua ishara na maelezo na sanidi sampuli na uamuzi na bonyeza sampuli (hakikisha **Amplitude** imechaguliwa, kiwango cha ishara kilichogunduliwa kimeboreshwa na **Gadner clock recovery** imechaguliwa):

![](<../../.gitbook/assets/image (962).png>)

* **Sync to selection intervals** inamaanisha kuwa ikiwa awali ulichagua vipindi ili kupata kiwango cha ishara, kiwango hicho cha ishara kitatumika.
* **Manual** inamaanisha kuwa kiwango cha ishara kilichoonyeshwa kitatumika
* Katika **Fixed interval selection** unaweka idadi ya vipindi vinavyopaswa kuchaguliwa na inahesabu kiwango cha ishara kutoka hapo
* **Gadner clock recovery** kawaida ni chaguo bora, lakini bado unahitaji kuonyesha kiwango cha ishara karibu.

Kwa kubonyeza sampuli hii inaonekana:

![](<../../.gitbook/assets/image (641).png>)

Sasa, ili SigDigger ielewe **eneo** la kiwango cha kiwango cha habari unahitaji bonyeza kwenye **kiwango cha chini** na kudumisha bonyeza hadi kiwango kikubwa:

![](<../../.gitbook/assets/image (436).png>)

Ikiwa kungekuwa na mfano **4 tofauti za amplitude**, ungehitaji kusanidi **Bits per symbol kuwa 2** na kuchagua kutoka kwa ndogo hadi kubwa.

Hatimaye **kuongeza** **Zoom** na **kubadilisha ukubwa wa safu** unaweza kuona bits (na unaweza kuchagua yote na kunakili ili kupata bits zote):

![](<../../.gitbook/assets/image (273).png>)

Ikiwa ishara ina zaidi ya biti 1 kwa ishara (kwa mfano 2), SigDigger haina **njia ya kujua ni ishara ipi** 00, 01, 10, 11, kwa hivyo itatumia **rangi tofauti** kila moja (na ikiwa unakopi bits itatumia **namba kutoka 0 hadi 3**, utahitaji kuzitibu).

Pia, tumia **nambari** kama **Manchester**, na **juu+chini** inaweza kuwa **1 au 0** na chini+juu inaweza kuwa 1 au 0. Katika kesi hizo unahitaji **kutibu ups (1) na downs (0)** zilizopatikana kuchukua nafasi ya jozi za 01 au 10 kama 0s au 1s.

## Mfano wa FM

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Kufunua FM

#### Kuchunguza frekwensi na waveform

Mfano wa ishara inayotuma habari iliyopitishwa kwa FM:

![](<../../.gitbook/assets/image (722).png>)

Katika picha iliyopita unaweza kuona vizuri kuwa **frekwensi 2 zinatumika** lakini ikiwa **unaangalia** **waveform** huenda **usitambue kwa usahihi frekwensi 2 tofauti**:

![](<../../.gitbook/assets/image (714).png>)

Hii ni kwa sababu nilichukua ishara katika frekwensi zote, kwa hivyo moja ni karibu na nyingine kwa upande wa hasi:

![](<../../.gitbook/assets/image (939).png>)

Ikiwa frekwensi iliyosawazishwa iko **karibu na frekwensi moja kuliko nyingine** unaweza kuona kwa urahisi frekwensi 2 tofauti:

![](<../../.gitbook/assets/image (419).png>)

![](<../../.gitbook/assets/image (485).png>)

#### Kuchunguza histogram

Kwa kuchunguza histogram ya frekwensi ya ishara na habari unaweza kuona kwa urahisi ishara 2 tofauti:

![](<../../.gitbook/assets/image (868).png>)

Katika kesi hii ikiwa unachunguza **Amplitude histogram** utapata **amplitude moja tu**, kwa hivyo **haiwezi kuwa AM** (ikiwa unapata amplitudo nyingi inaweza kuwa kwa sababu ishara imepoteza nguvu kwenye njia):

![](<../../.gitbook/assets/image (814).png>)

Na hii itakuwa histogram ya awamu (ambayo inafanya iwe wazi sana kuwa ishara haijapitishwa kwa awamu):

![](<../../.gitbook/assets/image (993).png>)

#### Na IQ

IQ haina uga wa kutambua frekwensi (umbali kutoka kati ni amplitude na pembe ni awamu).\
Kwa hivyo, kutambua FM, unapaswa **kuona msingi wa mduara tu** kwenye grafu hii.\
Zaidi ya hayo, frekwensi tofauti "inawakilishwa" na grafu ya IQ kwa **kasi ya kuongezeka kwenye mduara** (kwa hivyo katika SysDigger kuchagua ishara grafu ya IQ inajazwa, ikiwa unapata kasi ya kuongezeka au mabadiliko ya mwelekeo kwenye mduara ulioundwa inaweza maanisha kuwa hii ni FM):

![](<../../.gitbook/assets/image (78).png>)

### Pata Kiwango cha Ishara

Unaweza kutumia **njia ile ile iliyotumiwa katika mfano wa AM** kupata kiwango cha ishara mara tu unapopata frekwensi zinazobeba ishara.

### Pata Bits

Unaweza kutumia **njia ile ile iliyotumiwa katika mfano wa AM** kupata bits mara tu unapopata **ishara imepitishwa kwa frekwensi** na **kiwango cha ishara**.
