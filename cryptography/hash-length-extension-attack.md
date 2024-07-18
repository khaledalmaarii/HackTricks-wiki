{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}


# Opsomming van die aanval

Stel jou voor 'n bediener wat **data** onderteken deur 'n **geheim** by 'n bekende teksdata te **voeg** en dan daardie data te has. As jy weet:

* **Die lengte van die geheim** (dit kan ook afgedwing word van 'n gegewe lengte-reeks)
* **Die teksdata**
* **Die algoritme (en dit is vatbaar vir hierdie aanval)**
* **Die opvulling is bekend**
* Gewoonlik word 'n verstek een gebruik, so as die ander 3 vereistes voldoen is, is dit ook
* Die opvulling varieer afhangende van die lengte van die geheim+data, daarom is die lengte van die geheim nodig

Dan is dit moontlik vir 'n **aanvaller** om **data** by te **voeg** en 'n geldige **handtekening** te **genereer** vir die **vorige data + bygevoegde data**.

## Hoe?

Basies genereer die vatbare algoritmes die hasse deur eerstens 'n blok data te **has**, en dan, **van** die **voorheen** geskepte **has** (toestand), voeg hulle die volgende blok data by en **has dit**.

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


{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
