# Padding Oracle

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## CBC - Cipher Block Chaining

In CBC-modus word die **vorige versleutelde blok as IV** gebruik om met die volgende blok te XOR:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

Om CBC te dekripteer word die **teenoorgestelde** **operasies** gedoen:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Let op dat dit nodig is om 'n **versleutelingsleutel** en 'n **IV** te gebruik.

## Boodskapvulling

Aangesien die versleuteling in **vaste** **grootteblokke** uitgevoer word, is **vulling** gewoonlik nodig in die **laaste blok** om sy lengte te voltooi.\
Gewoonlik word **PKCS7** gebruik, wat 'n vulling genereer wat die **aantal benodigde bytes herhaal** om die blok te **voltooi**. Byvoorbeeld, as die laaste blok 3 bytes kortkom, sal die vulling `\x03\x03\x03` wees.

Laat ons na meer voorbeelde kyk met 'n **2 blokke van lengte 8 byte**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Let op hoe in die laaste voorbeeld die **laaste blok vol was, dus is nog een gegenereer slegs met vulling**.

## Padding Oracle

Wanneer 'n toepassing versleutelde data dekripteer, sal dit eers die data dekripteer; dan sal dit die vulling verwyder. Tydens die opruiming van die vulling, as 'n **ongeldige vulling 'n waarneembare gedrag veroorsaak**, het jy 'n **padding-orakel kwesbaarheid**. Die waarneembare gedrag kan 'n **fout**, 'n **gebrek aan resultate**, of 'n **stadiger reaksie** wees.

As jy hierdie gedrag opspoor, kan jy die **versleutelde data dekripteer** en selfs **enige klaarteks versleutel**.

### Hoe om te benut

Jy kan [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) gebruik om hierdie soort kwesbaarheid te benut of net die
```
sudo apt-get install padbuster
```
Om te toets of die koekie van 'n webwerf kwesbaar is, kan jy probeer:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Kodering 0** beteken dat **base64** gebruik word (maar ander is beskikbaar, kyk na die hulpmenu).

Jy kan ook **misbruik maak van hierdie kwesbaarheid om nuwe data te enkripteer. Byvoorbeeld, stel jou voor dat die inhoud van die koekie is "**_**gebruiker=MynGebruikersnaam**_**", dan kan jy dit verander na "\_gebruiker=administrateur\_" en voorregte binne die aansoek verhoog. Jy kan dit ook doen deur `paduster` te gebruik en die -plaintext** parameter te spesifiseer:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Indien die webwerf kwesbaar is, sal `padbuster` outomaties probeer om te vind wanneer die vullingsfout plaasvind, maar jy kan ook die foutboodskap aandui deur die **-error** parameter te gebruik.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
### Die teorie

In **opsomming**, kan jy begin om die versleutelde data te ontsluit deur te raai na die korrekte waardes wat gebruik kan word om al die **verskillende paddings** te skep. Dan sal die padding-orakelaanval begin om bytes van die einde na die begin te ontsluit deur te raai watter die korrekte waarde sal wees wat **'n padding van 1, 2, 3, ens. skep**.

![](<../.gitbook/assets/image (558).png>)

Stel jou voor jy het 'n paar versleutelde teks wat **2 blokke** beslaan wat gevorm word deur die bytes van **E0 tot E15**.\
Om die **laaste blok** (**E8** tot **E15**) te **ontsleutel**, gaan die hele blok deur die "blok-sifer ontsleuteling" wat die **tussenganger bytes I0 tot I15** genereer.\
Uiteindelik word elke tussenganger byte **XORed** met die vorige versleutelde bytes (E0 tot E7). So:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Nou is dit moontlik om **`E7` te wysig totdat `C15` `0x01` is**, wat ook 'n korrekte padding sal wees. Dus, in hierdie geval: `\x01 = I15 ^ E'7`

Dus, deur `E'7` te vind, is dit **moontlik om I15 te bereken**: `I15 = 0x01 ^ E'7`

Wat ons toelaat om **C15 te bereken**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Wetende **C15**, is dit nou moontlik om **C14 te bereken**, maar hierdie keer deur die padding `\x02\x02` te brute-force.

Hierdie BF is so kompleks soos die vorige een aangesien dit moontlik is om die `E''15` te bereken waarvan die waarde 0x02 is: `E''7 = \x02 ^ I15` dus dit is net nodig om die **`E'14`** te vind wat 'n **`C14` gelyk aan `0x02`** genereer.\
Doen dan dieselfde stappe om C14 te ontsluit: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Volg hierdie ketting totdat jy die hele versleutelde teks ontsluit.**

### Opmerking van die kwesbaarheid

Registreer 'n rekening en teken in met hierdie rekening.\
As jy **baie kere in teken** en altyd dieselfde koekie kry, is daar waarskynlik **iets fout** in die aansoek. Die **teruggestuurde koekie moet elke keer uniek** wees wanneer jy in teken. As die koekie **altyd** dieselfde is, sal dit waarskynlik altyd geldig wees en daar **sal geen manier wees om dit ongeldig te maak** nie.

Nou, as jy probeer om die koekie te **verander**, kan jy sien dat jy 'n **fout** van die aansoek kry.\
Maar as jy die padding brute-force (deur byvoorbeeld padbuster te gebruik) kan jy 'n ander koekie kry wat geldig is vir 'n ander gebruiker. Hierdie scenario is hoogs waarskynlik kwesbaar vir padbuster.

### Verwysings

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)

<details>

<summary><strong>Leer AWS hak van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
