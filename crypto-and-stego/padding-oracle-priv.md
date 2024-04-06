<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka sifuri hadi bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# CBC - Cipher Block Chaining

Katika mode ya CBC, **block iliyotangulia iliyofichwa hutumiwa kama IV** ya XOR na block inayofuata:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

Kwa kufichua CBC, **operesheni za kinyume** zinafanywa:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Tambua jinsi inavyohitajika kutumia **funguo za kufichua** na **IV**.

# Kupamba Ujumbe

Kwa kuwa kufichua kunafanywa kwa **vipande vya ukubwa uliowekwa**, **pamba** kawaida inahitajika kwenye **block ya mwisho** ili kukamilisha urefu wake.\
Kawaida **PKCS7** hutumiwa, ambayo inazalisha pamba **inayorudia** **idadi** ya **baiti** **inayohitajika** kukamilisha block. Kwa mfano, ikiwa block ya mwisho inakosa byte 3, pamba itakuwa `\x03\x03\x03`.

Tuangalie mifano zaidi na **vipande 2 vya urefu wa 8baiti**:

| namba ya byte #0 | namba ya byte #1 | namba ya byte #2 | namba ya byte #3 | namba ya byte #4 | namba ya byte #5 | namba ya byte #6 | namba ya byte #7 | namba ya byte #0  | namba ya byte #1  | namba ya byte #2  | namba ya byte #3  | namba ya byte #4  | namba ya byte #5  | namba ya byte #6  | namba ya byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Tambua jinsi katika mfano wa mwisho **block ya mwisho ilikuwa kamili kwa hivyo nyingine ilizalishwa tu na pamba**.

# Padding Oracle

Wakati programu inafichua data iliyofichwa, kwanza itaifichua data; kisha itaondoa pamba. Wakati wa kusafisha pamba, ikiwa **pamba batili inasababisha tabia inayoweza kugundulika**, una **mdudu wa padding oracle**. Tabia inayoweza kugundulika inaweza kuwa **kosa**, **ukosefu wa matokeo**, au **majibu polepole**.

Ikiwa unagundua tabia hii, unaweza **kufichua data iliyofichwa** na hata **kuficha maandishi wazi yoyote**.

## Jinsi ya kufaidika

Unaweza kutumia [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) kufaidika na aina hii ya mdudu au tu fanya
```
sudo apt-get install padbuster
```
Ili kujaribu kama kuki ya tovuti ina kasoro, unaweza kujaribu:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Ukodishaji 0** una maana kwamba **base64** inatumika (lakini nyingine zinapatikana, angalia menyu ya msaada).

Unaweza pia **kutumia udhaifu huu kuweka data mpya. Kwa mfano, fikiria kuwa maudhui ya kuki ni "**_**mtumiaji=JinaLanguLaMtumiaji**_**", basi unaweza kubadilisha kuwa "\_mtumiaji=msimamizi\_" na kuongeza mamlaka ndani ya programu. Unaweza pia kufanya hivyo kwa kutumia `paduster` ukitaja -plaintext** kama parameter:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Ikiwa tovuti ina kasoro, `padbuster` itajaribu kiotomatiki kupata wakati kosa la padding linatokea, lakini unaweza pia kuonyesha ujumbe wa kosa kwa kutumia kipengele cha **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## Nadharia

Kwa kifupi, unaweza kuanza kufichua data iliyofichwa kwa kudhani thamani sahihi ambazo zinaweza kutumika kuunda **paddings tofauti** zote. Kisha, shambulio la padding oracle litianza kufichua herufi kutoka mwisho hadi mwanzo kwa kudhani ni thamani ipi sahihi ambayo **inaunda padding ya 1, 2, 3, nk**.

![](<../.gitbook/assets/image (629) (1) (1).png>)

Fikiria una maandishi yaliyofichwa ambayo yanachukua **vikundi 2** vilivyoundwa na herufi kutoka **E0 hadi E15**.\
Ili **kufichua** **kikundi** **cha mwisho** (**E8** hadi **E15**), kikundi kizima kinapitia "ufichuzi wa block cipher" na kuzalisha **herufi za kati I0 hadi I15**.\
Hatimaye, kila herufi ya kati inafanyiwa **XOR** na herufi zilizofichwa hapo awali (E0 hadi E7). Hivyo:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Sasa, ni **inawezekana kubadilisha `E7` hadi `C15` iwe `0x01`**, ambayo pia itakuwa padding sahihi. Kwa hivyo, katika kesi hii: `\x01 = I15 ^ E'7`

Kwa hivyo, kwa kupata E'7, ni **inawezekana kuhesabu I15**: `I15 = 0x01 ^ E'7`

Hii inaturuhusu kuhesabu C15: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Kwa kujua **C15**, sasa ni **inawezekana kuhesabu C14**, lakini wakati huu kwa kubadilisha padding `\x02\x02`.

BF hii ni ngumu kama ile ya awali kwani inawezekana kuhesabu E''15 ambayo thamani yake ni 0x02: `E''7 = \x02 ^ I15` kwa hivyo inahitajika tu kupata **`E'14`** ambayo inazalisha **`C14` sawa na `0x02`**.\
Kisha, fanya hatua sawa za kufichua C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Fuata mnyororo huu hadi ufichue maandishi yote yaliyofichwa.**

## Uchunguzi wa udhaifu

Jisajili na akaunti na ingia kwa akaunti hiyo.\
Ikiwa unajisajili mara nyingi na daima unapata **cookie ile ile**, kuna uwezekano mkubwa kuna **kitu kibaya** katika programu. Kuki inayotumwa inapaswa kuwa **tofauti** kila wakati unapoingia. Ikiwa kuki **daima** ni **ile ile**, itakuwa inawezekana daima kuwa halali na **hakutakuwa na njia ya kuitengua**.

Sasa, ikiwa jaribu **kubadilisha** kuki, utaona kuwa unapata **kosa** kutoka kwa programu.\
Lakini ikiwa unatumia BF kwenye padding (kwa kutumia padbuster kwa mfano) unaweza kupata kuki nyingine halali kwa mtumiaji tofauti. Hali hii ina uwezekano mkubwa wa kuwa na udhaifu wa padbuster.

## Marejeo

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
