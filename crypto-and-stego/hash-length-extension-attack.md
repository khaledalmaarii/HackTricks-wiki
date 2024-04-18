<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is 'n **dark-web** aangedrewe soekenjin wat **gratis** funksies bied om te kontroleer of 'n maatskappy of sy kliënte deur **diewe-malware** gekompromitteer is.

Die primêre doel van WhiteIntel is om rekening-oorneeminge en lospryse-aanvalle te beveg wat voortspruit uit inligtingsteel-malware.

Jy kan hul webwerf besoek en hul enjin vir **gratis** probeer by:

{% embed url="https://whiteintel.io" %}

---

# Opsomming van die aanval

Stel jou 'n bediener voor wat **data** **onderteken** deur 'n **geheim** by 'n bekende teksdata te **voeg** en dan daardie data te has. As jy weet:

* **Die lengte van die geheim** (dit kan ook afgedwing word vanaf 'n gegewe lengte-reeks)
* **Die teksdata**
* **Die algoritme (en dit is vatbaar vir hierdie aanval)**
* **Die opvulling is bekend**
* Gewoonlik word 'n verstek een gebruik, dus as die ander 3 vereistes voldoen is, is dit ook
* Die opvulling varieer afhangende van die lengte van die geheim+data, daarom is die lengte van die geheim nodig

Dan is dit vir 'n **aanvaller** moontlik om **data** by te **voeg** en 'n geldige **handtekening** te **genereer** vir die **vorige data + bygevoegde data**.

## Hoe?

Basies genereer die vatbare algoritmes die hasse deur eerstens 'n blok data te has, en dan, **van** die **voorheen** geskepte **has** (toestand), voeg hulle die volgende blok data by en has dit.

Stel jou voor dat die geheim "geheim" is en die data "data" is, die MD5 van "geheimdata" is 6036708eba0d11f6ef52ad44e8b74d5b.\
As 'n aanvaller die string "byvoeg" wil byvoeg, kan hy:

* Genereer 'n MD5 van 64 "A"s
* Verander die toestand van die voorheen geïnisialiseerde has na 6036708eba0d11f6ef52ad44e8b74d5b
* Voeg die string "byvoeg" by
* Voltooi die has en die resulterende has sal 'n **geldige een wees vir "geheim" + "data" + "opvulling" + "byvoeg"**

## **Gereedskap**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Verwysings

Jy kan hierdie aanval goed verduidelik vind in [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is 'n **dark-web** aangedrewe soekenjin wat **gratis** funksies bied om te kontroleer of 'n maatskappy of sy kliënte deur **diewe-malware** gekompromitteer is.

Die primêre doel van WhiteIntel is om rekening-oorneeminge en lospryse-aanvalle te beveg wat voortspruit uit inligtingsteel-malware.

Jy kan hul webwerf besoek en hul enjin vir **gratis** probeer by:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
