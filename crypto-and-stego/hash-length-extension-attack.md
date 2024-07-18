# Hash Length Extension Attack

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is 'n **dark-web** aangedrewe soekenjin wat **gratis** funksies bied om te kyk of 'n maatskappy of sy kliënte **gekompromitteer** is deur **stealer malwares**.

Hul primêre doel van WhiteIntel is om rekening oorname en ransomware-aanvalle te bekamp wat voortspruit uit inligting-steel malware.

Jy kan hul webwerf besoek en hul enjin **gratis** probeer by:

{% embed url="https://whiteintel.io" %}

***

## Samevatting van die aanval

Stel jou 'n bediener voor wat **onderteken** sekere **data** deur 'n **geheime** by 'n bekende duidelike teksdata te voeg en dan daardie data te hash. As jy weet:

* **Die lengte van die geheim** (dit kan ook gebruteforceer word vanaf 'n gegewe lengterange)
* **Die duidelike teksdata**
* **Die algoritme (en dit is kwesbaar vir hierdie aanval)**
* **Die padding is bekend**
* Gewoonlik word 'n standaard een gebruik, so as die ander 3 vereistes nagekom word, is dit ook
* Die padding wissel afhangende van die lengte van die geheim+data, daarom is die lengte van die geheim nodig

Dan is dit moontlik vir 'n **aanvaller** om **data** by te voeg en 'n geldige **handtekening** te genereer vir die **vorige data + bygevoegde data**.

### Hoe?

Basies genereer die kwesbare algoritmes die hashes deur eerstens **'n blok data te hash**, en dan, **uit** die **voorheen** geskepte **hash** (toestand), voeg hulle **die volgende blok data** by en **hash dit**.

Stel jou voor dat die geheim "geheim" is en die data "data", die MD5 van "geheimdata" is 6036708eba0d11f6ef52ad44e8b74d5b.\
As 'n aanvaller die string "voeg by" wil byvoeg, kan hy:

* 'n MD5 van 64 "A"s genereer
* Die toestand van die voorheen geïnitialiseerde hash verander na 6036708eba0d11f6ef52ad44e8b74d5b
* Die string "voeg by" byvoeg
* Die hash voltooi en die resultaat sal 'n **geldige een wees vir "geheim" + "data" + "padding" + "voeg by"**

### **Gereedskap**

{% embed url="https://github.com/iagox86/hash_extender" %}

### Verwysings

Jy kan hierdie aanval goed verduidelik vind in [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is 'n **dark-web** aangedrewe soekenjin wat **gratis** funksies bied om te kyk of 'n maatskappy of sy kliënte **gekompromitteer** is deur **stealer malwares**.

Hul primêre doel van WhiteIntel is om rekening oorname en ransomware-aanvalle te bekamp wat voortspruit uit inligting-steel malware.

Jy kan hul webwerf besoek en hul enjin **gratis** probeer by:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
