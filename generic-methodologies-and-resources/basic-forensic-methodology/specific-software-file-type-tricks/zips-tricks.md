# ZIPs truuks

{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

**Opdraglynhulpmiddels** vir die bestuur van **zip-lêers** is noodsaaklik vir die diagnose, herstel, en kraak van zip-lêers. Hier is 'n paar sleutelgereedskap:

- **`unzip`**: Onthul waarom 'n zip-lêer moontlik nie kan dekomprimeer nie.
- **`zipdetails -v`**: Bied 'n gedetailleerde analise van zip-lêerformaatvelde.
- **`zipinfo`**: Lys inhoud van 'n zip-lêer sonder om dit uit te pak.
- **`zip -F input.zip --out output.zip`** en **`zip -FF input.zip --out output.zip`**: Probeer om beskadigde zip-lêers te herstel.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: 'n Gereedskap vir bruto-kragkraak van zip-wagwoorde, effektief vir wagwoorde tot ongeveer 7 karakters.

Die [Zip-lêerformaat spesifikasie](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) bied omvattende besonderhede oor die struktuur en standaarde van zip-lêers.

Dit is krities om daarop te let dat wagwoordbeskermde zip-lêers **nie lêernaam of lêergroottes versleutel nie** binne-in nie, 'n sekuriteitsgebrek wat nie gedeel word met RAR- of 7z-lêers wat hierdie inligting versleutel nie. Verder is zip-lêers wat met die ouer ZipCrypto-metode versleutel is, vatbaar vir 'n **platte tekst-aanval** as 'n onversleutelde kopie van 'n saamgepersde lêer beskikbaar is. Hierdie aanval maak gebruik van die bekende inhoud om die wagwoord van die zip te kraak, 'n kwesbaarheid wat in detail beskryf word in [HackThis se artikel](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) en verder verduidelik word in [hierdie akademiese artikel](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Nietemin, zip-lêers wat beveilig is met **AES-256**-versleuteling is immuun teen hierdie platte tekst-aanval, wat die belang van die kies van veilige versleutelingsmetodes vir sensitiewe data toon.

## Verwysings
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/) 

{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
