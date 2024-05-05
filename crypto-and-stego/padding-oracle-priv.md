# Oracle ya Padding

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## CBC - Cipher Block Chaining

Katika modi ya CBC **block iliyotangulia iliyofanyiwa encryption hutumiwa kama IV** ya XOR na block inayofuata:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

Kwa kudecrypt CBC **operesheni za kinyume** hufanywa:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Tambua jinsi inavyohitajika kutumia **ufunguo wa encryption** na **IV**.

## Kupangilia Ujumbe

Kwa kuwa encryption inafanywa katika **blocks za saizi iliyowekwa**, **padding** mara nyingi inahitajika katika **block ya mwisho** ili kukamilisha urefu wake.\
Kawaida **PKCS7** hutumiwa, ambayo inazalisha padding **inayorudia** **idadi** ya **bytes** **inayohitajika** kukamilisha block. Kwa mfano, ikiwa block ya mwisho inakosa bytes 3, padding itakuwa `\x03\x03\x03`.

Tuangalie mifano zaidi na **blocks 2 zenye urefu wa 8bytes**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Tambua jinsi katika mfano wa mwisho **block ya mwisho ilikuwa kamili hivyo nyingine ilizalishwa tu na padding**.

## Oracle ya Padding

Wakati programu inadecrypt data iliyofanyiwa encryption, kwanza itadecrypt data; kisha itaondoa padding. Wakati wa kusafisha padding, ikiwa **padding isiyo halali inachochea tabia inayoweza kugundulika**, una **udhaifu wa oracle ya padding**. Tabia inayoweza kugundulika inaweza kuwa **kosa**, **ukosefu wa matokeo**, au **jibu polepole**.

Ukigundua tabia hii, unaweza **kudecrypt data iliyofanyiwa encryption** na hata **kufanya encryption ya maandishi wazi yoyote**.

### Jinsi ya kutumia

Unaweza kutumia [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) kudukua aina hii ya udhaifu au tu fanya
```
sudo apt-get install padbuster
```
Ili kujaribu kama kuki ya tovuti ina mapungufu unaweza kujaribu:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Ukodishaji 0** maana yake **base64** inatumika (ingawa nyingine zinapatikana, angalia menyu ya msaada).

Unaweza pia **kutumia udhaifu huu kwa kuficha data mpya. Kwa mfano, fikiria maudhui ya kuki ni "**_**mtumiaji=JinaLanguLaMtumiaji**_**", basi unaweza kubadilisha kuwa "\_mtumiaji=msimamizi\_" na kuinua mamlaka ndani ya programu. Unaweza pia kufanya hivyo ukitumia `paduster` ukielekeza kipengele cha -plaintext:**
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Ikiwa tovuti ina kasoro `padbuster` itajaribu kiotomatiki kupata wakati kosa la padding linatokea, lakini unaweza pia kuashiria ujumbe wa kosa kwa kutumia parameter ya **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
### Nadharia

Kwa **muhtasari**, unaweza kuanza kufichua data iliyofichwa kwa kudhani thamani sahihi ambayo inaweza kutumika kuunda **paddings tofauti** zote. Kisha, shambulio la padding oracle litianza kufichua herufi kutoka mwisho hadi mwanzo kwa kudhani ni thamani sahihi ambayo **inaunda padding ya 1, 2, 3, nk**.

![](<../.gitbook/assets/image (561).png>)

Fikiria una maandishi yaliyofichwa ambayo yanachukua **vikundi 2** vilivyoundwa na herufi kutoka **E0 hadi E15**.\
Ili **kufichua** **kikundi cha mwisho** (**E8** hadi **E15**), kikundi nzima hupitia "ufichuaji wa block cipher" ukizalisha **herufi za kati I0 hadi I15**.\
Hatimaye, kila herufi ya kati ina **XORed** na herufi zilizofichwa hapo awali (E0 hadi E7). Hivyo:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Sasa, Inawezekana **kubadilisha `E7` hadi `C15` iwe `0x01`**, ambayo pia itakuwa padding sahihi. Hivyo, katika kesi hii: `\x01 = I15 ^ E'7`

Hivyo, kwa kupata E'7, ni **inawezekana kuhesabu I15**: `I15 = 0x01 ^ E'7`

Hii inaruhusu sisi **kuhesabu C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Kwa kujua **C15**, sasa ni **inawezekana kuhesabu C14**, lakini wakati huu kwa kubadilisha nguvu padding `\x02\x02`.

BF hii ni ngumu kama ile ya awali kwa sababu inawezekana kuhesabu **`E''15` ambayo thamani yake ni 0x02: `E''7 = \x02 ^ I15` hivyo ni muhimu tu kupata **`E'14`** ambayo inazalisha **`C14` sawa na `0x02`**.\
Kisha, fanya hatua sawa kufichua C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Fuata mnyororo huu hadi ufichue maandishi yote yaliyofichwa.**

### Kugundua udhaifu

Jisajili akaunti na ingia kwa akaunti hiyo.\
Ikiwa **unaingia mara nyingi** na daima unapata **cookie sawa**, kuna uwezekano **kitu** **hakiko sawa** katika programu. **Cookie inayotumwa inapaswa kuwa ya kipekee** kila wakati unapoingia. Ikiwa cookie ni **sawa daima**, itakuwa uwezekano daima kuwa halali na **hakutakuwa na njia ya kuitengua**.

Sasa, ikiwa jaribu **kubadilisha** **cookie**, utaona unapata **kosa** kutoka kwa programu.\
Lakini ikiwa unatumia BF ya padding (kwa kutumia padbuster kwa mfano) unaweza kupata cookie nyingine halali kwa mtumiaji tofauti. Hali hii inaweza kuwa na uwezekano mkubwa wa kuwa na udhaifu wa padbuster.

### Marejeo

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
