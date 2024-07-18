# Geheue dump analise

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is die mees relevante kuberveiligheid gebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n bruisende ontmoetingspunt vir tegnologie en kuberveiligheid professionele in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

## Begin

Begin **soek** na **malware** binne die pcap. Gebruik die **gereedskap** genoem in [**Malware Analise**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility is die hoof open-source raamwerk vir geheue dump analise**. Hierdie Python gereedskap analiseer dumps van eksterne bronne of VMware VM's, wat data soos prosesse en wagwoorde identifiseer gebaseer op die dump se OS profiel. Dit is uitbreidbaar met plugins, wat dit baie veelsydig maak vir forensiese ondersoeke.

[**Vind hier 'n cheatsheet**](volatility-cheatsheet.md)

## Mini dump crash verslag

Wanneer die dump klein is (net 'n paar KB, dalk 'n paar MB) dan is dit waarskynlik 'n mini dump crash verslag en nie 'n geheue dump nie.

![](<../../../.gitbook/assets/image (532).png>)

As jy Visual Studio geïnstalleer het, kan jy hierdie lêer oopmaak en 'n paar basiese inligting soos prosesnaam, argitektuur, uitsondering inligting en modules wat uitgevoer word bind:

![](<../../../.gitbook/assets/image (263).png>)

Jy kan ook die uitsondering laai en die gedecompileerde instruksies sien

![](<../../../.gitbook/assets/image (142).png>)

![](<../../../.gitbook/assets/image (610).png>)

In elk geval, Visual Studio is nie die beste gereedskap om 'n analise van die diepte van die dump uit te voer nie.

Jy moet dit **oopmaak** met **IDA** of **Radare** om dit in **diepte** te inspekteer.

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is die mees relevante kuberveiligheid gebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n bruisende ontmoetingspunt vir tegnologie en kuberveiligheid professionele in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
