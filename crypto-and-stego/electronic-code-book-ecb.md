<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# ECB

(ECB) Kitabu cha Nambari cha Umeme - mfumo wa kusimbua wa usawa ambao **badala kila kibodi cha maandishi wazi** na **kibodi ya maandishi ya siri**. Ni mfumo wa kusimbua wa **rahisi zaidi**. Wazo kuu ni **kugawanya** maandishi wazi katika **vibodi vya N bits** (inategemea ukubwa wa kibodi ya data ya kuingiza, algorithm ya kusimbua) na kisha kusimbua (kusimbua) kila kibodi cha maandishi wazi kwa kutumia ufunguo pekee.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

Kutumia ECB kuna athari za usalama nyingi:

* **Vibodi kutoka kwenye ujumbe uliosimbwa vinaweza kuondolewa**
* **Vibodi kutoka kwenye ujumbe uliosimbwa vinaweza kusogezwa**

# Ugunduzi wa udhaifu

Fikiria unaingia kwenye programu mara kadhaa na unapata **kuki ile ile kila wakati**. Hii ni kwa sababu kuki ya programu ni **`<jina la mtumiaji>|<nywila>`**.\
Kisha, unazalisha watumiaji wapya, wote wakiwa na **nywila ndefu ile ile** na **karibu** **jina la mtumiaji** **lile lile**.\
Unagundua kuwa **vibodi za 8B** ambapo **habari ya watumiaji wote** ni sawa ni **sawa**. Kisha, unafikiria kuwa hii inaweza kuwa kwa sababu **ECB inatumika**.

Kama katika mfano ufuatao. Tazama jinsi **kuki hizi 2 zilizosimbwa** zina mara kadhaa kibodi **`\x23U\xE45K\xCB\x21\xC8`**
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
Hii ni kwa sababu **jina la mtumiaji na nenosiri la vidakuzi hivyo vilikuwa na herufi "a" mara kadhaa** (kwa mfano). **Vidokezo** ambavyo ni **tofauti** ni vidokezo ambavyo vilikuwa na **angalau herufi moja tofauti** (labda kizuizi "|" au tofauti muhimu katika jina la mtumiaji).

Sasa, mshambuliaji anahitaji tu kugundua ikiwa muundo ni `<jina la mtumiaji><kizuizi><nenosiri>` au `<nenosiri><kizuizi><jina la mtumiaji>`. Kufanya hivyo, anaweza tu **kuunda majina mengi ya mtumiaji** na majina ya mtumiaji na nywila **yenye urefu sawa na mrefu** hadi atapata muundo na urefu wa kizuizi:

| Urefu wa Jina la Mtumiaji: | Urefu wa Nenosiri: | Urefu wa Jina la Mtumiaji+Nenosiri: | Urefu wa Kidakuzi (baada ya kudecode): |
| ------------------------- | ----------------- | ----------------------------------- | ------------------------------------- |
| 2                         | 2                 | 4                                   | 8                                     |
| 3                         | 3                 | 6                                   | 8                                     |
| 3                         | 4                 | 7                                   | 8                                     |
| 4                         | 4                 | 8                                   | 16                                    |
| 7                         | 7                 | 14                                  | 16                                    |

# Utekaji wa udhaifu

## Kuondoa vikundi vyote

Kwa kujua muundo wa kidakuzi (`<jina la mtumiaji>|<nenosiri>`), ili kujifanya kuwa jina la mtumiaji `admin`, tumia mtumiaji mpya aliyeitwa `aaaaaaaaadmin` na pata kidakuzi na kudecode:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Tunaweza kuona mfano `\x23U\xE45K\xCB\x21\xC8` uliotengenezwa hapo awali na jina la mtumiaji ambalo lilikuwa na `a` pekee.\
Kisha, unaweza kuondoa kibodi ya kwanza ya 8B na utapata kuki halali kwa jina la mtumiaji `admin`:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Kuhamisha vitengo

Katika database nyingi, ni sawa kutafuta `WHERE username='admin';` au `WHERE username='admin    ';` _(Tafadhali kumbuka nafasi za ziada)_

Kwa hivyo, njia nyingine ya kujifanya kuwa mtumiaji `admin` itakuwa:

* Tengeneza jina la mtumiaji ambalo: `len(<username>) + len(<delimiter) % len(block)`. Kwa ukubwa wa vitengo wa `8B` unaweza kutengeneza jina la mtumiaji linaloitwa: `username       `, na kipengee cha kugawanya `|` kipande `<username><delimiter>` kitazalisha vitengo 2 vya 8Bs.
* Kisha, tengeneza nenosiri ambalo litajaza idadi kamili ya vitengo vinavyo zaweza jina la mtumiaji tunayotaka kujifanya kuwa ni nafasi, kama vile: `admin   `

Kidakuzi cha mtumiaji huyu kitajumuisha vitengo 3: vya kwanza 2 ni vitengo vya jina la mtumiaji + kipengee cha kugawanya na cha tatu ni nenosiri (ambalo linajifanya kuwa jina la mtumiaji): `username       |admin   `

**Kisha, tuweke kipengee cha kwanza na cha mwisho na tutakuwa tunajifanya kuwa mtumiaji `admin`: `admin          |username`**

## Marejeo

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
