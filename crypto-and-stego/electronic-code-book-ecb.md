{% hint style="success" %}
Jifunze na zoea AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Timu Nyekundu Mtaalam (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoea GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Timu Nyekundu Mtaalam (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha** [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


# ECB

(ECB) Kitabu cha Msimbo wa Kielektroniki - mpango wa kuficha wa kisimetri unaobadilisha kila kibodi cha maandishi wazi kwa kibodi ya maandishi yaliyofichwa. Ni mpango wa kuficha **rahisishi**. Wazo kuu ni **kugawa** maandishi wazi katika **vibodi vya N bits** (inategemea saizi ya kibodi ya data ya kuingia, algorithm ya kuficha) na kisha kuficha (kufichua) kila kibodi ya maandishi wazi kwa kutumia funguo pekee.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

Kutumia ECB kuna athari nyingi za usalama:

* **Vibodi kutoka ujumbe uliofichwa vinaweza kuondolewa**
* **Vibodi kutoka ujumbe uliofichwa vinaweza kuhamishwa**

# Kugundua udhaifu

Fikiria unaingia kwenye programu mara kadhaa na **unapata kuki ile ile** kila wakati. Hii ni kwa sababu kuki ya programu ni **`<jina la mtumiaji>|<nywila>`**.\
Kisha, unazalisha watumiaji wapya, wote wawili wakiwa na **nywila ndefu sawa** na **karibu** **jina la mtumiaji** **sawa**.\
Unagundua kwamba **vibodi za 8B** ambapo **taarifa za watumiaji wote** ni sawa ni **sawa**. Kisha, unafikiria kwamba hii inaweza kuwa kwa sababu **ECB inatumika**.

Kama katika mfano ufuatao. Angalia jinsi hizi **kuki 2 zilizofichuliwa** zina mara nyingi kibodi **`\x23U\xE45K\xCB\x21\xC8`**
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
Hii ni kwa sababu **jina la mtumiaji na nywila ya vidakuzi hivyo vilikuwa na mara nyingi herufi "a"** (kwa mfano). **Vipande** ambavyo ni **tofauti** ni vipande vilivyokuwa na **angalau herufi 1 tofauti** (labda kizuizi "|" au tofauti muhimu katika jina la mtumiaji).

Sasa, mshambuliaji anahitaji tu kugundua ikiwa muundo ni `<jina la mtumiaji><kizuizi><nywila>` au `<nywila><kizuizi><jina la mtumiaji>`. Ili kufanya hivyo, anaweza tu **kuunda majina mengi ya mtumiaji** na **majina ya mtumiaji na nywila ndefu na sawa** hadi apate muundo na urefu wa kizuizi:

| Urefu wa Jina la Mtumiaji: | Urefu wa Nywila: | Urefu wa Jina la Mtumiaji+Nywila: | Urefu wa Kuki (baada ya kudecode): |
| --------------------------- | ---------------- | ---------------------------------- | ----------------------------------- |
| 2                           | 2                | 4                                  | 8                                   |
| 3                           | 3                | 6                                  | 8                                   |
| 3                           | 4                | 7                                  | 8                                   |
| 4                           | 4                | 8                                  | 16                                  |
| 7                           | 7                | 14                                 | 16                                  |

# Kutumia Udhaifu

## Kuondoa vipande vyote

Kwa kujua muundo wa kuki (`<jina la mtumiaji>|<nywila>`), ili kujifanya kuwa jina la mtumiaji `admin` unaweza kuunda mtumiaji mpya aitwaye `aaaaaaaaadmin` na kupata kuki na kuidecode:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Tunaweza kuona mfano `\x23U\xE45K\xCB\x21\xC8` uliozalishwa hapo awali na jina la mtumiaji lililokuwa na `a` pekee.\
Kisha, unaweza kuondoa kibodi cha kwanza cha 8B na utapata kuki halali kwa jina la mtumiaji `admin`:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Kuhamisha vitalu

Katika mifumo mingi ya database ni sawa kutafuta `WHERE username='admin';` au `WHERE username='admin    ';` _(Kumbuka nafasi za ziada)_

Kwa hivyo, njia nyingine ya kujifanya kuwa mtumiaji `admin` itakuwa:

* Tengeneza jina la mtumiaji ambalo: `len(<username>) + len(<delimiter) % len(block)`. Kwa ukubwa wa block wa `8B` unaweza kutengeneza jina la mtumiaji liitwalo: `username       `, na delimiter `|` kipande `<username><delimiter>` kitazalisha vitalu 2 vya 8Bs.
* Kisha, tengeneza nenosiri litakaloweka idadi kamili ya vitalu vinavyoleta pamoja jina la mtumiaji tunayetaka kujifanya kuwa yeye na nafasi, kama: `admin   `

Cookie ya mtumiaji huyu itakuwa imeundwa na vitalu 3: vya kwanza 2 ni vitalu vya jina la mtumiaji + delimiter na cha tatu ni cha nenosiri (ambacho kinajifanya kuwa jina la mtumiaji): `username       |admin   `

**Kisha, tuweke vitalu vya kwanza na vile vya mwisho na tutakuwa tukijifanya kuwa mtumiaji `admin`: `admin          |username`**

## Marejeo

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))
