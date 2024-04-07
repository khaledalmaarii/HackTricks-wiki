# Ander Web Truuks

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

### Gasheerkop

Verskeie kere vertrou die agterkant die **Gasheerkop** om sekere aksies uit te voer. Byvoorbeeld, dit kan sy waarde gebruik as die **domein om 'n wagwoordterugstelling te stuur**. Dus, wanneer jy 'n e-pos met 'n skakel ontvang om jou wagwoord te herstel, is die domein wat gebruik word die een wat jy in die Gasheerkop gesit het. Dan kan jy die wagwoordherstel van ander gebruikers aanvra en die domein verander na een wat deur jou beheer word om hul wagwoordherstelkodes te steel. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Let daarop dat dit moontlik is dat jy nie eens hoef te wag vir die gebruiker om op die wagwoordherstelskakel te klik om die token te kry nie, aangesien miskien selfs **spampatrone of ander tussenliggende toestelle/botte daarop sal klik om dit te analiseer**.
{% endhint %}

### Sessie-booleans

Soms, wanneer jy 'n sekere verifikasie korrek voltooi, sal die agterkant net 'n booleaan met die waarde "Waar" by 'n sekuriteitsatribuut van jou sessie **byvoeg**. Dan sal 'n ander eindpunt weet of jy daardie toets suksesvol geslaag het.\
Maar, as jy **die toets slaag** en jou sessie daardie "Waar" waarde in die sekuriteitsatribuut kry, kan jy probeer om **toegang te verkry tot ander bronne** wat **afhanklik is van dieselfde atribuut** maar waarvoor jy **nie toestemmings behoort te hê om toegang te verkry nie**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Registreerfunksionaliteit

Probeer om te registreer as 'n reeds bestaande gebruiker. Probeer ook om ekwivalente karakters te gebruik (punte, baie spasies en Unicode).

### Oorname van e-posse

Registreer 'n e-pos, voordat jy dit bevestig, verander die e-pos, dan, as die nuwe bevestigingse-pos na die eerste geregistreerde e-pos gestuur word, kan jy enige e-pos oorneem. Of as jy die tweede e-pos kan aktiveer wat die eerste een bevestig, kan jy ook enige rekening oorneem.

### Toegang tot die interne diensverskaffer van maatskappye wat Atlassian gebruik

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE-metode

Ontwikkelaars kan vergeet om verskeie foutopsporingsopsies in die produksie-omgewing uit te skakel. Byvoorbeeld, die HTTP `TRACE`-metode is ontwerp vir diagnostiese doeleindes. Indien geaktiveer, sal die webbediener reageer op versoeke wat die `TRACE`-metode gebruik deur die presiese versoek wat ontvang is, in die antwoord te herhaal. Hierdie gedrag is dikwels onskadelik, maar lei soms tot die bekendmaking van inligting, soos die naam van interne outentiseringskoppe wat by versoek deur omgekeerde proksi's aangeheg kan word.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)
