{% hint style="success" %}
Leer & oefen AWS Hack: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}


# CBC

Indien die **koekie** slegs die **gebruikersnaam** is (of die eerste deel van die koekie die gebruikersnaam is) en jy wil die gebruikersnaam "**admin**" naboots. Dan kan jy die gebruikersnaam **"bdmin"** skep en die **eerste byte** van die koekie **bruteforce**.

# CBC-MAC

**Cipher block chaining message authentication code** (**CBC-MAC**) is 'n metode wat in kriptografie gebruik word. Dit werk deur 'n boodskap te neem en dit blok vir blok te enkripteer, waar elke blok se enkripsie gekoppel is aan die een voor dit. Hierdie proses skep 'n **ketting van blokke**, wat verseker dat selfs 'n enkele bit van die oorspronklike boodskap verander, sal lei tot 'n onvoorspelbare verandering in die laaste blok van enkripteerde data. Om so 'n verandering te maak of omkeer, is die enkripsiesleutel nodig, wat sekuriteit verseker.

Om die CBC-MAC van boodskap m te bereken, enkripteer mens m in CBC-modus met 'n nul-inisialiseringsvektor en hou die laaste blok. Die volgende figuur skets die berekening van die CBC-MAC van 'n boodskap wat uit blokke bestaan ![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) met 'n geheime sleutel k en 'n blok-sif E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Kwesbaarheid

Met CBC-MAC is die **IV wat gebruik word gewoonlik 0**.\
Dit is 'n probleem omdat 2 bekende boodskappe (`m1` en `m2`) onafhanklik 2 handtekeninge (`s1` en `s2`) sal genereer. So:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Dan sal 'n boodskap saamgestel deur m1 en m2 aanmekaar te sit (m3) 2 handtekeninge genereer (s31 en s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Dit is moontlik om sonder om die enkripsiesleutel te ken, te bereken.**

Stel jou voor jy enkripteer die naam **Administrator** in **8 byte** blokke:

* `Administ`
* `rator\00\00\00`

Jy kan 'n gebruikersnaam genaamd **Administ** (m1) skep en die handtekening (s1) herwin.\
Dan kan jy 'n gebruikersnaam skep wat die resultaat is van `rator\00\00\00 XOR s1`. Dit sal `E(m2 XOR s1 XOR 0)` genereer wat s32 is.\
Nou kan jy s32 gebruik as die handtekening van die volledige naam **Administrator**.

### Opsomming

1. Kry die handtekening van gebruikersnaam **Administ** (m1) wat s1 is
2. Kry die handtekening van gebruikersnaam **rator\x00\x00\x00 XOR s1 XOR 0** is s32**.**
3. Stel die koekie in op s32 en dit sal 'n geldige koekie wees vir die gebruiker **Administrator**.

# Aanval Beheer IV

As jy die gebruikte IV kan beheer, kan die aanval baie maklik wees.\
As die koekies net die gebruikersnaam enkripteer is, om die gebruiker "**administrator**" na te boots, kan jy die gebruiker "**Administrator**" skep en jy sal sy koekie kry.\
Nou, as jy die IV kan beheer, kan jy die eerste Byte van die IV verander sodat **IV\[0] XOR "A" == IV'\[0] XOR "a"** en hergenereer die koekie vir die gebruiker **Administrator.** Hierdie koekie sal geldig wees om die gebruiker **administrator** met die aanvanklike **IV** na te boots.

## Verwysings

Meer inligting in [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


{% hint style="success" %}
Leer & oefen AWS Hack: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
