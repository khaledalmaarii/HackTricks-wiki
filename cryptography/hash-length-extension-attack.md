<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>


# Opsomming van die aanval

Stel jou voor 'n bediener wat 'n paar **data** onderteken deur 'n **geheim** by 'n bekende teksdata te **voeg** en dan daardie data te hash. As jy weet:

* **Die lengte van die geheim** (dit kan ook gekraak word binne 'n gegewe lengtebereik)
* **Die duidelike teksdata**
* **Die algoritme (en dit is vatbaar vir hierdie aanval)**
* **Die opvulling is bekend**
* Gewoonlik word 'n verstek een gebruik, so as die ander 3 vereistes voldoen word, is dit ook die geval
* Die opvulling varieer afhangende van die lengte van die geheim+data, daarom is die lengte van die geheim nodig

Dan is dit moontlik vir 'n **aanvaller** om **data** by te voeg en 'n geldige **handtekening** te genereer vir die **vorige data + bygevoegde data**.

## Hoe?

Basies genereer die vatbare algoritmes die hasings deur eerstens 'n blok data te hash, en dan, **van** die **voorheen** geskep **hash** (toestand), voeg hulle die volgende blok data by en hash dit.

Stel jou voor dat die geheim "geheim" is en die data "data" is, die MD5 van "geheimdata" is 6036708eba0d11f6ef52ad44e8b74d5b.\
As 'n aanvaller die string "byvoeg" wil byvoeg, kan hy:

* Genereer 'n MD5 van 64 "A"s
* Verander die toestand van die voorheen geïnisialiseerde hash na 6036708eba0d11f6ef52ad44e8b74d5b
* Voeg die string "byvoeg" by
* Voltooi die hash en die resulterende hash sal 'n **geldige een wees vir "geheim" + "data" + "opvulling" + "byvoeg"**

## **Hulpmiddel**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Verwysings

Jy kan hierdie aanval goed verduidelik vind by [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
