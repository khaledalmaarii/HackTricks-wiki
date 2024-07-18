{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>unga mkono HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


# CBC - Cipher Block Chaining

Katika modi ya CBC **block iliyotangulia iliyofichwa hutumiwa kama IV** ya XOR na block inayofuata:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

Kufichua CBC **operesheni za kinyume** hufanywa:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Tambua jinsi inavyohitajika kutumia **ufunguo wa kufichua** na **IV**.

# Kupangilia Ujumbe

Kwa kuwa kufichua kunafanywa katika **blocki zenye saizi** **zilizowekwa**, **padding** mara nyingi inahitajika katika **blocki ya mwisho** ili kukamilisha urefu wake.\
Kawaida **PKCS7** hutumiwa, ambayo inazalisha padding **inayorudia** **idadi** ya **bayti** **inayohitajika** **kukamilisha** blocki. Kwa mfano, ikiwa blocki ya mwisho inakosa bayti 3, padding itakuwa `\x03\x03\x03`.

Tuangalie mifano zaidi na **blocki 2 zenye urefu wa bayti 8**:

| bayti #0 | bayti #1 | bayti #2 | bayti #3 | bayti #4 | bayti #5 | bayti #6 | bayti #7 | bayti #0  | bayti #1  | bayti #2  | bayti #3  | bayti #4  | bayti #5  | bayti #6  | bayti #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Tambua jinsi katika mfano wa mwisho **blocki ya mwisho ilikuwa kamili hivyo nyingine ilizalishwa tu na padding**.

# Oracle ya Padding

Wakati programu inafichua data iliyofichwa, kwanza itaifichua data; kisha itaondoa padding. Wakati wa kusafisha padding, ikiwa **padding batili inachochea tabia inayoweza kugundulika**, una **udhaifu wa oracle ya padding**. Tabia inayoweza kugundulika inaweza kuwa **kosa**, **ukosefu wa matokeo**, au **jibu polepole**.

Ukigundua tabia hii, unaweza **kufichua data iliyofichwa** na hata **kuficha maandishi wazi**.

## Jinsi ya kutumia

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
Ikiwa tovuti ina kasoro, `padbuster` itajaribu moja kwa moja kugundua wakati kosa la padding linatokea, lakini unaweza pia kuashiria ujumbe wa kosa kwa kutumia parameter **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## Nadharia

Kwa **muhtasari**, unaweza kuanza kufichua data iliyofichwa kwa kudhani thamani sahihi ambazo zinaweza kutumika kuunda **paddings tofauti** zote. Kisha, shambulio la oracle la padding litianza kufichua bytes kutoka mwisho hadi mwanzo kwa kudhani ni thamani sahihi ambayo **inaunda padding ya 1, 2, 3, nk**.

![](<../.gitbook/assets/image (629) (1) (1).png>)

Fikiria una maandishi yaliyofichwa ambayo yanachukua **vikundi 2** vilivyoundwa na bytes kutoka **E0 hadi E15**.\
Ili **kufichua** **kikundi cha mwisho** (**E8** hadi **E15**), kikundi nzima hupitia "ufichuaji wa block cipher" ukizalisha **bytes za kati I0 hadi I15**.\
Hatimaye, kila byte ya kati inafanyiwa **XOR** na bytes zilizofichwa hapo awali (E0 hadi E7). Hivyo:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Sasa, Inawezekana **kurekebisha `E7` hadi `C15` iwe `0x01`**, ambayo pia itakuwa padding sahihi. Hivyo, katika kesi hii: `\x01 = I15 ^ E'7`

Hivyo, kwa kupata E'7, ni **inawezekana kuhesabu I15**: `I15 = 0x01 ^ E'7`

Hii inaruhusu sisi **kuhesabu C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Kwa kujua **C15**, sasa ni **inawezekana kuhesabu C14**, lakini wakati huu kwa kubadilisha padding `\x02\x02`.

BF hii ni ngumu kama ile ya awali kwani inawezekana kuhesabu **`E''15` ambayo thamani yake ni 0x02: `E''7 = \x02 ^ I15` hivyo ni muhimu tu kupata **`E'14`** ambayo inazalisha **`C14` sawa na `0x02`**.\
Kisha, fanya hatua sawa kufichua C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Fuata mnyororo huu hadi ufichue maandishi yote yaliyofichwa.**

## Kugundua udhaifu

Jisajili na akaunti na ingia kwa akaunti hiyo.\
Ikiwa **unaingia mara nyingi** na daima unapata **cookie ile ile**, kuna uwezekano **kitu** **hakiko sawa** katika programu. Cookie inayotumwa inapaswa kuwa **tofauti** kila wakati unapoingia. Ikiwa cookie ni **ile ile daima**, itakuwa inawezekana daima kuwa halali na **hakutakuwa na njia ya kuitengua**.

Sasa, ikiwa jaribu **kurekebisha** **cookie**, utaona unapata **kosa** kutoka kwa programu.\
Lakini ikiwa unatumia BF ya padding (kwa kutumia padbuster kwa mfano) unaweza kupata cookie nyingine halali kwa mtumiaji tofauti. Hali hii inawezekana sana kuwa na udhaifu wa padbuster.

## Marejeo

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)
