# Ander Web Truuks

{% hint style="success" %}
Leer & oefen AWS Hack: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

### Gasheerkop

Verskeie kere vertrou die agterkant die **Gasheerkop** om sekere aksies uit te voer. Byvoorbeeld, dit kan sy waarde gebruik as die **domein om 'n wagwoordterugstelling te stuur**. Dus, wanneer jy 'n e-pos met 'n skakel ontvang om jou wagwoord te herstel, is die domein wat gebruik word die een wat jy in die Gasheerkop gesit het. Dan kan jy die wagwoordherstel van ander gebruikers aanvra en die domein na een wat deur jou beheer word, verander om hul wagwoordherstelkodes te steel. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Let daarop dat dit moontlik is dat jy nie eens hoef te wag vir die gebruiker om op die wagwoordterugstellingskakel te klik om die token te kry nie, aangesien miskien selfs **spampatrone of ander tussenliggende toestelle/bots daarop sal klik om dit te analiseer**.
{% endhint %}

### Sessie-booleans

Soms, wanneer jy 'n sekere verifikasie korrek voltooi, sal die agterkant net 'n booleaan met die waarde "Waar" by 'n sekuriteitsatribuut in jou sessie **byvoeg**. Dan sal 'n ander eindpunt weet of jy daardie toets suksesvol geslaag het.\
Maar, as jy **die toets slaag** en jou sessie daardie "Waar" waarde in die sekuriteitsatribuut kry, kan jy probeer om **toegang tot ander bronne** te kry wat **afhanklik is van dieselfde atribuut** maar waarvoor jy **nie toestemmings** behoort te hê om toegang te verkry nie. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Registreerfunksionaliteit

Probeer om as 'n reeds bestaande gebruiker te registreer. Probeer ook om ekwivalente karakters (kolletjies, baie spasies en Unicode) te gebruik.

### Oorname van e-posse

Registreer 'n e-pos, verander dit voordat jy dit bevestig, dan, as die nuwe bevestigingse-pos na die eerste geregistreerde e-pos gestuur word, kan jy enige e-pos oorneem. Of as jy die tweede e-pos kan aktiveer wat die eerste een bevestig, kan jy ook enige rekening oorneem.

### Toegang tot die interne diensverskaffer van maatskappye wat Atlassian gebruik

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE-metode

Ontwikkelaars kan vergeet om verskeie foutopsporingsopsies in die produksie-omgewing uit te skakel. Byvoorbeeld, die HTTP `TRACE`-metode is ontwerp vir diagnostiese doeleindes. Indien geaktiveer, sal die webbediener reageer op versoeke wat die `TRACE`-metode gebruik deur in die antwoord die presiese versoek wat ontvang is, te herhaal. Hierdie gedrag is dikwels onskadelik, maar lei soms tot inligtingsoffers, soos die naam van interne outentiseringskoppe wat by versoek deur omgekeerde proksies aangeheg kan word.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


{% hint style="success" %}
Leer & oefen AWS Hack: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
