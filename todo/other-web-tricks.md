# Ander Web Truuks

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

### Host-kop

Verskeie kere vertrou die agterkant op die **Host-kop** om sekere aksies uit te voer. Byvoorbeeld, dit kan die waarde gebruik as die **domein om 'n wagwoordherstel te stuur**. So wanneer jy 'n e-pos ontvang met 'n skakel om jou wagwoord te herstel, is die domein wat gebruik word die een wat jy in die Host-kop plaas. Dan kan jy die wagwoordherstel van ander gebruikers aanvra en die domein verander na een wat deur jou beheer word om hul wagwoordherstelkodes te steel. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Let daarop dat dit moontlik is dat jy nie eens hoef te wag vir die gebruiker om op die wagwoordherstelskakel te klik om die token te kry nie, aangesien **spamfilters of ander tussenliggende toestelle/bots dit dalk self sal klik om dit te analiseer**.
{% endhint %}

### Sessie-booleans

Soms, as jy sekere verifikasie korrek voltooi, sal die agterkant eenvoudig 'n booleaan met die waarde "True" by 'n sekuriteitsatribuut in jou sessie voeg. Dan sal 'n ander eindpunt weet of jy daardie toets suksesvol geslaag het.\
Maar as jy die toets **slaag** en jou sessie daardie "True"-waarde in die sekuriteitsatribuut het, kan jy probeer om **ander hulpbronne** te **benader wat afhang van dieselfde atribuut**, maar waarvoor jy **nie toestemmings behoort te hê** nie. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Registreer-funksionaliteit

Probeer registreer as 'n reeds bestaande gebruiker. Probeer ook ekwivalente karakters (punte, baie spasies en Unicode) gebruik.

### Oorname van e-posse

Registreer 'n e-pos, verander dit voordat dit bevestig word, dan, as die nuwe bevestigingse-pos na die eerste geregistreerde e-pos gestuur word, kan jy enige e-pos oorneem. Of as jy die tweede e-pos kan aktiveer wat die eerste een bevestig, kan jy ook enige rekening oorneem.

### Toegang tot die interne servicedesk van maatskappye wat Atlassian gebruik

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE-metode

Ontwikkelaars kan vergeet om verskeie foutopsporingsopsies in die produksie-omgewing uit te skakel. Byvoorbeeld, die HTTP `TRACE`-metode is ontwerp vir diagnostiese doeleindes. As dit geaktiveer is, sal die webbediener reageer op versoeke wat die `TRACE`-metode gebruik deur die presiese versoek wat ontvang is in die antwoord te herhaal. Hierdie gedrag is dikwels onskadelik, maar lei soms tot die bekendmaking van inligting, soos die naam van interne outentiseringskoppe wat deur omgekeerde proksi's by versoeke gevoeg kan word.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
