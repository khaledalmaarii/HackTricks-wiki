# macOS Rooi-span

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## MDM-misbruik

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

As jy daarin slaag om **administratiewe legitimasie te kompromitteer** om toegang tot die bestuursplatform te verkry, kan jy **moontlik alle rekenaars kompromitteer** deur jou kwaadwillige sagteware op die masjiene te versprei.

Vir rooi-spanning in MacOS-omgewings word dit sterk aanbeveel om 'n basiese begrip van hoe die MDM's werk te hê:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### MDM gebruik as 'n C2

'n MDM het toestemming om profiele te installeer, navrae te doen of te verwyder, programme te installeer, plaaslike administrateursrekeninge te skep, firmware-wagwoord te stel, die FileVault-sleutel te verander...

Om jou eie MDM te laat loop, moet jy **jou CSR deur 'n verskaffer laat onderteken** wat jy kan probeer kry met [**https://mdmcert.download/**](https://mdmcert.download/). En om jou eie MDM vir Apple-toestelle te laat loop, kan jy [**MicroMDM**](https://github.com/micromdm/micromdm) gebruik.

Om egter 'n toepassing op 'n ingeskryfde toestel te installeer, moet dit steeds deur 'n ontwikkelaarsrekening onderteken word... maar met MDM-inskrywing voeg die **toestel die SSL-sertifikaat van die MDM as 'n vertroude CA by**, sodat jy nou enigiets kan onderteken.

Om die toestel in 'n MDM in te skryf, moet jy 'n **`mobileconfig`**-lêer as root installeer, wat afgelewer kan word deur 'n **pkg**-lêer (jy kan dit in 'n zip-komprimeer en wanneer dit vanaf Safari afgelaai word, sal dit gedekomprimeer word).

**Mythic-agent Orthrus** gebruik hierdie tegniek.

### JAMF PRO-misbruik

JAMF kan **aangepaste skripte** (skripte wat deur die stelseladministrateur ontwikkel is), **inheemse ladinge** (skep van plaaslike rekeninge, stel EFI-wagwoord, lêer-/prosesmonitering...) en **MDM** (toestelkonfigurasies, toestelsertifikate...) uitvoer.

#### JAMF selfinskrywing

Gaan na 'n bladsy soos `https://<company-name>.jamfcloud.com/enroll/` om te sien of hulle **selfinskrywing geaktiveer** het. As hulle dit het, kan dit **vra vir legitimasie om toegang te verkry**.

Jy kan die skrip [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) gebruik om 'n wagwoordspuitaanval uit te voer.

Verder, nadat jy die regte legitimasie gevind het, kan jy moontlik ander gebruikersname met die volgende vorm deur kragtige kragtige aanvalle aanval:

![](<../../.gitbook/assets/image (7) (1) (1).png>)

#### JAMF-toestelverifikasie

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Die **`jamf`** binêre lêer bevat die geheim om die sleutelketting oop te maak wat op daardie tydstip **gedeel** was onder almal en dit was: **`jk23ucnq91jfu9aj`**.\
Verder volharder jamf as 'n **LaunchDaemon** in **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF-toesteloorgawe

Die **JSS** (Jamf Software Server) **URL** wat **`jamf`** sal gebruik, is geleë in **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Hierdie lêer bevat basies die URL:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

So, 'n aanvaller kan 'n skadelike pakkie (`pkg`) laat val wat **hierdie lêer oorskryf** wanneer dit geïnstalleer word en die **URL instel op 'n Mythic C2 luisteraar van 'n Typhon-agent** om nou JAMF te misbruik as C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF Impersonation

Om die kommunikasie tussen 'n toestel en JMF na te boots, benodig jy die volgende:

* Die **UUID** van die toestel: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* Die **JAMF-sleutelbos** vanaf: `/Library/Application\ Support/Jamf/JAMF.keychain` wat die toestelsertifikaat bevat

Met hierdie inligting, **skep 'n VM** met die **gesteelde** Hardeware **UUID** en met **SIP gedeaktiveer**, laat die **JAMF-sleutelbos val**, **haak** die Jamf **agent** en steel sy inligting.

#### Geheimhouding steel

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

Jy kan ook die ligging `/Library/Application Support/Jamf/tmp/` monitor vir die **aangepaste skripte** wat administrateurs dalk wil uitvoer via Jamf aangesien hulle hier **geplaas, uitgevoer en verwyder** word. Hierdie skripte **kan geloofsbriewe bevat**.

Nietemin, **geloofsbriewe** kan aan hierdie skripte oorgedra word as **parameters**, dus sal jy `ps aux | grep -i jamf` moet monitor (sonder om selfs root te wees).

Die skrip [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) kan luister vir nuwe lêers wat bygevoeg word en nuwe prosesargumente.

### macOS Afstandsbediening

En ook oor **MacOS** "spesiale" **netwerkprotokolle**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Aktiewe Gids

In sommige gevalle sal jy vind dat die **MacOS-rekenaar aan 'n AD gekoppel is**. In hierdie scenario moet jy probeer om die aktiewe gids soos jy gewoond is te **opnoem**. Vind 'n bietjie **hulp** in die volgende bladsye:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Sommige **plaaslike MacOS-hulpmiddels** wat jou ook kan help, is `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Daar is ook 'n paar gereedgemaakte hulpmiddels vir MacOS om outomaties die AD te ondersoek en met kerberos te speel:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound is 'n uitbreiding van die Bloodhound ouditeringshulpmiddel wat die insameling en opname van Active Directory-verhoudings op MacOS-gashere moontlik maak.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost is 'n Objective-C-projek wat ontwerp is om met die Heimdal krb5 API's op macOS te kommunikeer. Die doel van die projek is om beter sekuriteitstoetsing rondom Kerberos op macOS-toestelle moontlik te maak deur gebruik te maak van inheemse API's sonder om enige ander raamwerk of pakkette op die teiken te vereis.
* [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript vir Automatisering (JXA) hulpmiddel vir Active Directory-ondersoek.

### Domein Inligting
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Gebruikers

Die drie tipes MacOS-gebruikers is:

* **Plaaslike Gebruikers** - Bestuur deur die plaaslike OpenDirectory-diens, hulle is op geen manier gekoppel aan die Aktiewe Gids nie.
* **Netwerkgebruikers** - Vlugtige Aktiewe Gids-gebruikers wat 'n verbinding met die DC-bediener benodig om te verifieer.
* **Mobiele Gebruikers** - Aktiewe Gids-gebruikers met 'n plaaslike rugsteun vir hul geloofsbriewe en lêers.

Die plaaslike inligting oor gebruikers en groepe word gestoor in die map _/var/db/dslocal/nodes/Default._\
Byvoorbeeld, die inligting oor 'n gebruiker genaamd _mark_ word gestoor in _/var/db/dslocal/nodes/Default/users/mark.plist_ en die inligting oor die groep _admin_ is in _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Bo en behalwe die gebruik van die HasSession en AdminTo-lyne, **voeg MacHound drie nuwe lyne by** tot die Bloodhound-databasis:

* **CanSSH** - entiteit wat toegelaat word om SSH na gasheer te maak
* **CanVNC** - entiteit wat toegelaat word om VNC na gasheer te maak
* **CanAE** - entiteit wat toegelaat word om AppleEvent-skripsies op gasheer uit te voer
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Meer inligting in [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

## Toegang tot die Sleutelbos

Die Sleutelbos bevat hoogstwaarskynlik sensitiewe inligting wat, as dit sonder 'n vraag gegenereer word, kan help om 'n rooi-span-oefening voort te sit:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Eksterne Dienste

MacOS Red Teaming verskil van 'n gewone Windows Red Teaming omdat gewoonlik **MacOS geïntegreer is met verskeie eksterne platforms direk**. 'n Gewone konfigurasie van MacOS is om toegang tot die rekenaar te verkry deur gebruik te maak van **OneLogin-gesinkroniseerde geloofsbriewe en toegang tot verskeie eksterne dienste** (soos github, aws...) via OneLogin.

## Verskeie Red Team-tegnieke

### Safari

Wanneer 'n lêer in Safari afgelaai word, sal dit as dit 'n "veilige" lêer is, **outomaties oopgemaak** word. So byvoorbeeld, as jy 'n zip aflaai, sal dit outomaties gedekomprimeer word:

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## Verwysings

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks in PDF aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-klere**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
