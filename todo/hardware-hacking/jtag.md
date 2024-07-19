# JTAG

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)ni chombo kinachoweza kutumika na Raspberry PI au Arduino kutafuta kujaribu pini za JTAG kutoka kwa chip isiyojulikana.\
Katika **Arduino**, ung'anishe **pini kutoka 2 hadi 11 kwa pini 10 zinazoweza kuwa za JTAG**. Pakia programu kwenye Arduino na itajaribu kujaribu nguvu zote za pini ili kuona kama pini yoyote inahusiana na JTAG na ambayo ni kila moja.\
Katika **Raspberry PI** unaweza kutumia tu **pini kutoka 1 hadi 6** (pini 6, hivyo utachukua muda mrefu zaidi kujaribu kila pini inayoweza kuwa ya JTAG).

### Arduino

Katika Arduino, baada ya kuunganisha nyaya (pini 2 hadi 11 kwa pini za JTAG na GND ya Arduino kwa GND ya baseboard), **pakia programu ya JTAGenum kwenye Arduino** na katika Monitor ya Serial tuma **`h`** (amri ya msaada) na unapaswa kuona msaada:

![](<../../.gitbook/assets/image (939).png>)

![](<../../.gitbook/assets/image (578).png>)

Sanidi **"No line ending" na 115200baud**.\
Tuma amri s kuanza skanning:

![](<../../.gitbook/assets/image (774).png>)

Ikiwa unawasiliana na JTAG, utaona moja au kadhaa **mistari inayohakikisha kuwa IMEPATIKANA!** ikionyesha pini za JTAG.

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
