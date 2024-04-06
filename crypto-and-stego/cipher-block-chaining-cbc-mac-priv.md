<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>


# CBC

As die **koekie** **slegs** die **gebruikersnaam** is (of die eerste deel van die koekie is die gebruikersnaam) en jy wil die gebruikersnaam "**admin**" naboots. Dan kan jy die gebruikersnaam **"bdmin"** skep en die **eerste byte** van die koekie **brute force**.

# CBC-MAC

**Cipher block chaining message authentication code** (**CBC-MAC**) is 'n metode wat in kriptografie gebruik word. Dit werk deur 'n boodskap blok vir blok te versleutel, waar elke blok se versleuteling gekoppel is aan die een voor dit. Hierdie proses skep 'n **ketting van blokke**, wat verseker dat selfs 'n enkele bit van die oorspronklike boodskap 'n onvoorspelbare verandering in die laaste blok van versleutelde data sal veroorsaak. Om so 'n verandering te maak of ongedaan te maak, is die versleutelingssleutel nodig, wat sekuriteit verseker.

Om die CBC-MAC van 'n boodskap m te bereken, word m in CBC-modus met 'n nul-inisialisasievektor versleutel en die laaste blok behou. Die volgende figuur skets die berekening van die CBC-MAC van 'n boodskap wat uit blokke bestaan![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) deur 'n geheime sleutel k en 'n blokversleuteling E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Kwesbaarheid

Met CBC-MAC word die **IV wat gebruik word, gewoonlik as 0** gestel.\
Dit is 'n probleem omdat 2 bekende boodskappe (`m1` en `m2`) onafhanklik 2 handtekeninge (`s1` en `s2`) sal genereer. So:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Dan sal 'n boodskap wat bestaan uit m1 en m2 gekombineer (m3) 2 handtekeninge genereer (s31 en s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Dit is moontlik om dit te bereken sonder om die versleutelingssleutel te ken.**

Stel jou voor jy versleutel die naam **Administrator** in blokke van **8 byte**:

* `Administ`
* `rator\00\00\00`

Jy kan 'n gebruikersnaam skep met die naam **Administ** (m1) en die handtekening (s1) daarvan bekom.\
Dan kan jy 'n gebruikersnaam skep met die resultaat van `rator\00\00\00 XOR s1`. Dit sal `E(m2 XOR s1 XOR 0)` genereer, wat s32 is.\
Nou kan jy s32 gebruik as die handtekening van die volledige naam **Administrator**.

### Opsomming

1. Kry die handtekening van die gebruikersnaam **Administ** (m1), wat s1 is.
2. Kry die handtekening van die gebruikersnaam **rator\x00\x00\x00 XOR s1 XOR 0**, wat s32 is.
3. Stel die koekie in as s32 en dit sal 'n geldige koekie wees vir die gebruiker **Administrator**.

# Aanval deur IV te beheer

As jy die gebruikte IV kan beheer, kan die aanval baie maklik wees.\
As die koekies net die versleutelde gebruikersnaam is, kan jy die gebruiker "**administrator**" naboots deur die gebruiker "**Administrator**" te skep en sy koekie te kry.\
Nou, as jy die IV kan beheer, kan jy die eerste byte van die IV verander sodat **IV\[0] XOR "A" == IV'\[0] XOR "a"** en die koekie vir die gebruiker **Administrator** hergenereer. Hierdie koekie sal geldig wees om die gebruiker **administrator** met die oorspronklike **IV** na te boots.

## Verwysings

Meer inligting in [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
