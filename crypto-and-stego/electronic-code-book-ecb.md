<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# ECB

(ECB) Kitabu cha Msimbo wa Elektroniki - mpango wa kuficha wa kisimetri unaobadilisha kila kibodi cha maandishi wazi kwa kibodi ya maandishi yaliyofichwa. Ni mpango wa kuficha **rahisishi**. Wazo kuu ni **kugawanya** maandishi wazi katika **vibodi vya N bits** (inategemea saizi ya kibodi ya data ya kuingia, algorithm ya kuficha) na kisha kuficha (kufichua) kila kibodi ya maandishi wazi kwa kutumia funguo pekee.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

Kutumia ECB kuna athari nyingi za usalama:

* **Vibodi kutoka kwenye ujumbe uliofichwa vinaweza kuondolewa**
* **Vibodi kutoka kwenye ujumbe uliofichwa vinaweza kuhamishwa**

# Kugundua udhaifu

Fikiria unajiingia kwenye programu mara kadhaa na **unapata kuki ile ile kila wakati**. Hii ni kwa sababu kuki ya programu ni **`<jina la mtumiaji>|<nywila>`**.\
Kisha, unazalisha watumiaji wapya, wote wawili wakiwa na **nywila ndefu ile ile** na **karibu** **jina la mtumiaji** **lile lile**.\
Unagundua kwamba **vibodi za 8B** ambapo **habari za watumiaji wote** ni sawa ni **sawa**. Kisha, unafikiria kwamba hii inaweza kuwa kwa sababu **ECB inatumika**.

Kama katika mfano ufuatao. Angalia jinsi hizi **kuki 2 zilizofichuliwa** zina mara nyingi kibodi **`\x23U\xE45K\xCB\x21\xC8`**
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
Hii ni kwa sababu **jina la mtumiaji na nywila ya vidakuzi hivyo vilikuwa na mara nyingi herufi "a"** (kwa mfano). **Vipande** ambavyo ni **tofauti** ni vipande vilivyokuwa na **angalau herufi 1 tofauti** (labda kizuizi "|" au tofauti muhimu katika jina la mtumiaji).

Sasa, mkaidi anahitaji tu kugundua ikiwa muundo ni `<jina la mtumiaji><kizuizi><nywila>` au `<nywila><kizuizi><jina la mtumiaji>`. Ili kufanya hivyo, anaweza tu **kuzalisha majina kadhaa ya mtumiaji** na **majina ya mtumiaji na nywila ndefu na sawa** hadi apate muundo na urefu wa kizuizi:

| Urefu wa Jina la Mtumiaji: | Urefu wa Nywila: | Urefu wa Jina la Mtumiaji+Nywila: | Urefu wa Kuki (baada ya kudecode): |
| --------------------------- | ---------------- | --------------------------------- | ----------------------------------- |
| 2                           | 2                | 4                                 | 8                                   |
| 3                           | 3                | 6                                 | 8                                   |
| 3                           | 4                | 7                                 | 8                                   |
| 4                           | 4                | 8                                 | 16                                  |
| 7                           | 7                | 14                                | 16                                  |

# Kutumia Udhaifu

## Kuondoa Vipande Vyote

Kwa kujua muundo wa kuki (`<jina la mtumiaji>|<nywila>`), ili kujifanya kuwa jina la mtumiaji `admin` tengeneza mtumiaji mpya aitwaye `aaaaaaaaadmin` na pata kuki na uidecode:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Tunaweza kuona mfano `\x23U\xE45K\xCB\x21\xC8` uliozalishwa hapo awali na jina la mtumiaji lililokuwa na `a` pekee.\
Kisha, unaweza kuondoa block ya kwanza ya 8B na utapata kidakuzi halali kwa jina la mtumiaji `admin`:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Kuhamisha vitengo

Katika mifumo mingi ya database ni sawa kutafuta `WHERE username='admin';` au `WHERE username='admin    ';` _(Kumbuka nafasi za ziada)_

Kwa hivyo, njia nyingine ya kujifanya kuwa mtumiaji `admin` ingekuwa:

* Tengeneza jina la mtumiaji ambalo: `len(<username>) + len(<delimiter) % len(block)`. Kwa saizi ya block ya `8B` unaweza kutengeneza jina la mtumiaji linaloitwa: `username       `, na delimiter `|` kipande `<username><delimiter>` kitazalisha block 2 za 8Bs.
* Kisha, tengeneza nenosiri litakaloweka idadi kamili ya blocks zinazoleta pamoja jina la mtumiaji tunayetaka kujifanya kuwa yeye na nafasi, kama: `admin   `

Cookie ya mtumiaji huyu itakuwa imeundwa na block 3: ya kwanza 2 ni block za jina la mtumiaji + delimiter na ya tatu ni ya nenosiri (ambalo linajifanya kuwa jina la mtumiaji): `username       |admin   `

**Kisha, tuibadilishe block ya kwanza na ya mwisho na tutakuwa tukijifanya kuwa mtumiaji `admin`: `admin          |username`**

## Marejeo

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))
