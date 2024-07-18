# macOS Rooi-spanning

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Rooi-spanningskenner (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Rooi-spanningskenner (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

## MDM's Misbruik

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

As jy daarin slaag om **administrateurskredentiale te kompromiteer** om toegang tot die bestuursplatform te verkry, kan jy moontlik al die rekenaars **kompromiteer deur jou malware in die toestelle te versprei**.

Vir rooi-spanning in MacOS-omgewings word dit sterk aanbeveel om 'n begrip te hê van hoe die MDM's werk:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### MDM as 'n C2 gebruik

'n MDM sal toestemming hê om profiele te installeer, navrae te doen of te verwyder, toepassings te installeer, plaaslike administrateursrekeninge te skep, firmwarewagwoord in te stel, die FileVault-sleutel te verander...

Om jou eie MDM te hardloop, moet jy **jou CSR deur 'n verkoper laat onderteken** wat jy kan probeer kry met [**https://mdmcert.download/**](https://mdmcert.download/). En om jou eie MDM vir Apple-toestelle te hardloop, kan jy [**MicroMDM**](https://github.com/micromdm/micromdm) gebruik.

Nogtans, om 'n toepassing op 'n ingeskryfde toestel te installeer, moet dit steeds deur 'n ontwikkelaarsrekening onderteken word... maar met MDM-inskrywing voeg die **toestel die SSL-sertifikaat van die MDM as 'n vertroude CA** by, sodat jy nou enigiets kan onderteken.

Om die toestel in 'n MDM in te skryf, moet jy 'n **`mobileconfig`**-lêer as root installeer, wat afgelewer kan word via 'n **pkg**-lêer (jy kan dit in 'n zip komprimeer en wanneer dit vanaf Safari afgelaai word, sal dit gedekomprimeer word).

**Mythiese agent Orthrus** gebruik hierdie tegniek.

### JAMF PRO Misbruik

JAMF kan **aangepaste skripte** (skripte ontwikkel deur die stelseladministrateur), **inheemse vragte** (plaaslike rekening skepping, stel EFI-wagwoord, lêer/proses monitering...) en **MDM** (toestelkonfigurasies, toestelsertifikate...) hardloop.

#### JAMF self-inskrywing

Gaan na 'n bladsy soos `https://<maatskappy-naam>.jamfcloud.com/enroll/` om te sien of hulle **self-inskrywing geaktiveer** het. As hulle dit het, kan dit **versoek om kredentiale te verkry**.

Jy kan die skrip [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) gebruik om 'n wagwoordspuitaanval uit te voer.

Verder, nadat jy die regte kredentiale gevind het, kan jy dalk ander gebruikersname met die volgende vorm kragtig maak:

![](<../../.gitbook/assets/image (107).png>)

#### JAMF toestelverifikasie

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

Die **`jamf`** binêre lêer het die geheim bevat om die sleutelhangertoegang oop te maak wat op daardie tydstip **gedeel** was onder almal en dit was: **`jk23ucnq91jfu9aj`**.\
Verder, bly jamf voort as 'n **LaunchDaemon** in **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF Toesteloorneem

Die **JSS** (Jamf Sagteware-bediener) **URL** wat **`jamf`** sal gebruik, is geleë in **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
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

Dus, 'n aanvaller kan 'n skadelike pakket (`pkg`) laat val wat **hierdie lêer oorskryf** wanneer dit geïnstalleer word deur die **URL na 'n Mythic C2 luisteraar van 'n Typhon agent** te stel om nou JAMF te misbruik as C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF Nabootsing

Ten einde die **kommunikasie te naboots** tussen 'n toestel en JMF benodig jy:

* Die **UUID** van die toestel: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* Die **JAMF sleutelhang** vanaf: `/Library/Application\ Support/Jamf/JAMF.keychain` wat die toestel sertifikaat bevat

Met hierdie inligting, **skep 'n VM** met die **gesteelde** Hardeware **UUID** en met **SIP gedeaktiveer**, laat die **JAMF sleutelhang val**, **hook** die Jamf **agent** en steel sy inligting.

#### Geheime steel

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Jy kan ook die ligging `/Library/Application Support/Jamf/tmp/` monitor vir die **aangepaste skripte** wat admins dalk wil uitvoer via Jamf aangesien hulle hier **geplaas, uitgevoer en verwyder** word. Hierdie skripte **mag kredensiale bevat**.

Nietemin, **kredensiale** mag deurgegee word aan hierdie skripte as **parameters**, dus sal jy `ps aux | grep -i jamf` moet monitor (sonder om selfs root te wees).

Die skrip [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) kan luister vir nuwe lêers wat bygevoeg word en nuwe proses argumente.

### macOS Afstandstoegang

En ook oor **MacOS** "spesiale" **netwerk** **protokolle**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Aktiewe Gids

In sommige gevalle sal jy vind dat die **MacOS-rekenaar aan 'n AD gekoppel is**. In hierdie scenario moet jy probeer om die aktiewe gids soos jy gewoond is te **opsom**. Vind bietjie **hulp** in die volgende bladsye:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Sommige **plaaslike MacOS-hulpmiddels** wat jou ook kan help is `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Daar is ook 'n paar gereedskap vir MacOS om outomaties die AD te ontleed en te speel met kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound is 'n uitbreiding van die Bloodhound ouditeringsgereedskap wat die insameling en opname van Aktiewe Advertensie-verhoudings op MacOS-gashere moontlik maak.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost is 'n Objective-C projek wat ontwerp is om met die Heimdal krb5 API's op macOS te interaksieer. Die doel van die projek is om beter sekuriteitstoetsing rondom Kerberos op macOS-toestelle moontlik te maak deur gebruik te maak van inheemse API's sonder om enige ander raamwerk of pakkette op die teiken te vereis.
* [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript vir Outomatisering (JXA) gereedskap om Aktiewe Advertensie-ontleding te doen.

### Domein Inligting
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Gebruikers

Die drie tipes MacOS-gebruikers is:

- **Plaaslike Gebruikers** - Bestuur deur die plaaslike OpenDirectory-diens, hulle is op geen enkele manier gekoppel aan die Aktiewe Gids nie.
- **Netwerkgebruikers** - Vlugtige Aktiewe Gids-gebruikers wat 'n verbinding met die DC-bediener benodig om te verifieer.
- **Mobiele Gebruikers** - Aktiewe Gids-gebruikers met 'n plaaslike rugsteun vir hul geloofsbriewe en lêers.

Die plaaslike inligting oor gebruikers en groepe word gestoor in die map _/var/db/dslocal/nodes/Default._\
Byvoorbeeld, die inligting oor 'n gebruiker genaamd _mark_ word gestoor in _/var/db/dslocal/nodes/Default/users/mark.plist_ en die inligting oor die groep _admin_ is in _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Benewens die gebruik van die HasSession en AdminTo kante, **MacHound voeg drie nuwe kante** by tot die Bloodhound-databasis:

- **CanSSH** - entiteit wat toegelaat word om SSH na gasheer te maak
- **CanVNC** - entiteit wat toegelaat word om VNC na gasheer te maak
- **CanAE** - entiteit wat toegelaat word om AppleEvent-skripte op gasheer uit te voer
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

## Toegang tot die Sleutelhang

Dit is baie waarskynlik dat die Sleutelhang sensitiewe inligting bevat wat, as dit sonder 'n versoek toegang kry, kan help om 'n rooi span-oefening voort te sit:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Eksterne Dienste

MacOS Red Teaming is anders as 'n gewone Windows Red Teaming omdat **MacOS gewoonlik geïntegreer is met verskeie eksterne platforms direk**. 'n Gewone konfigurasie van MacOS is om toegang tot die rekenaar te verkry deur **OneLogin gesinkroniseerde geloofsbriewe te gebruik, en toegang te verkry tot verskeie eksterne dienste** (soos github, aws...) via OneLogin.

## Verskeie Red Team tegnieke

### Safari

Wanneer 'n lêer in Safari afgelaai word, sal dit as dit 'n "veilige" lêer is, **outomaties oopgemaak** word. So byvoorbeeld, as jy 'n zip-lêer **aflaai**, sal dit outomaties gedekomprimeer word:

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## Verwysings

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Kom na die Donker Kant, Ons Het Appels: Die Omskakeling van macOS-bestuurskunde tot Boosheid**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "‘n Aanvaller se Perspektief op Jamf-konfigurasies" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

{% hint style="success" %}
Leer & oefen AWS-hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
