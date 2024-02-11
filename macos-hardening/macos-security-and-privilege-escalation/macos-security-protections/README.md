# macOS Sekuriteitsbeskerming

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>

## Gatekeeper

Gatekeeper word gewoonlik gebruik om te verwys na die kombinasie van **Quarantine + Gatekeeper + XProtect**, 3 macOS-sekuriteitsmodules wat sal probeer om **gebruikers te verhoed om potensieel skadelike sagteware af te laai en uit te voer**.

Meer inligting in:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Prosessbeperkings

### SIP - Sisteemintegriteitsbeskerming

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandboks

MacOS Sandboks **beperk die uitvoering van programme** binne die sandboks tot die **toegelate aksies wat in die Sandboks-profiel** gespesifiseer is. Dit help om te verseker dat **die toepassing slegs verwagte hulpbronne sal benader**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Deursigtigheid, Toestemming en Beheer**

**TCC (Deursigtigheid, Toestemming en Beheer)** is 'n sekuriteitsraamwerk. Dit is ontwerp om die toestemmings van programme te **bestuur**, spesifiek deur hul toegang tot sensitiewe funksies te reguleer. Dit sluit elemente soos **liggingdienste, kontakte, foto's, mikrofoon, kamera, toeganklikheid en volle skyf-toegang** in. TCC verseker dat programme slegs toegang tot hierdie funksies kan verkry nadat eksplisiete gebruikerstoestemming verkry is, wat privaatheid en beheer oor persoonlike data versterk.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Lancering/Omgewingsbeperkings & Vertrouenskas

Lanceringsbeperkings in macOS is 'n sekuriteitskenmerk om **prosesinleiding te reguleer** deur te bepaal **wie** 'n proses **kan begin**, **hoe** en **vanwaar**. Dit is in macOS Ventura bekendgestel en kategoriseer stelsel-binêre lêers in beperkingskategorieë binne 'n **vertrouenskas**. Elke uitvoerbare binêre lêer het **reëls** vir sy **lancering**, insluitend **self**, **ouer** en **verantwoordelike** beperkings. Uitgebrei na derdeparty-programme as **Omgewing**-beperkings in macOS Sonoma, help hierdie kenmerke om potensiële stelsel-uitbuitings te verminder deur proseslanceringsvoorwaardes te beheer.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Malware-verwyderingsinstrument

Die Malware-verwyderingsinstrument (MRT) is 'n ander deel van macOS se sekuriteitsinfrastruktuur. Soos die naam aandui, is die hooffunksie van MRT om bekende malware van geïnfekteerde stelsels te **verwyder**.

Sodra malware op 'n Mac opgespoor word (deur XProtect of op 'n ander manier), kan MRT gebruik word om die malware outomaties **te verwyder**. MRT werk stil in die agtergrond en loop gewoonlik wanneer die stelsel opgedateer word of wanneer 'n nuwe malware-definisie afgelaai word (dit lyk asof die reëls wat MRT gebruik om malware op te spoor binne die binêre lêer is).

Terwyl beide XProtect en MRT deel is van macOS se sekuriteitsmaatreëls, verrig hulle verskillende funksies:

* **XProtect** is 'n voorkomende instrument. Dit **kontroleer lêers terwyl hulle afgelaai word** (via sekere programme), en as dit enige bekende tipes malware opspoor, **voorkom dit dat die lêer oopgemaak word**, en voorkom dus dat die malware jou stelsel in die eerste plek infekteer.
* **MRT** is daarenteen 'n **reaktiewe instrument**. Dit werk nadat malware op 'n stelsel opgespoor is, met die doel om die skadelike sagteware te verwyder om die stelsel skoon te maak.

Die MRT-toepassing is geleë in **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Agtergrondtakenbestuur

**macOS** waarsku nou **elke keer as 'n instrument 'n bekende tegniek gebruik om kode-uitvoering vol te hou** (soos Aanmeldingsitems, Daemons...), sodat die gebruiker beter weet **watter sagteware volhou**.

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

Dit word uitgevoer met 'n **daemon** wat geleë is in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` en die **agent** in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Die manier waarop **`backgroundtaskmanagementd`** weet dat iets in 'n volhoubare vouer geïnstalleer is, is deur die **FSEvents te kry** en sommige **hanteraars** daarvoor te skep.

Daarbenewens is daar 'n plist-lêer wat **bekende programme** bevat wat gereeld volhou, onderhou
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumerasie

Dit is moontlik om **alle** geconfigureerde agtergronditems te ondersoek deur die Apple-opdraglynwerktuig uit te voer:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Verder is dit ook moontlik om hierdie inligting te lys met [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Hierdie inligting word gestoor in **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** en die Terminal benodig FDA.

### Speel met BTM

Wanneer 'n nuwe volharding gevind word, word 'n gebeurtenis van die tipe **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** gegenereer. Enige manier om hierdie gebeurtenis te **voorkom** om gestuur te word of om die **agent te verhoed om die gebruiker te waarsku**, sal 'n aanvaller help om BTM te _**omseil**_.

* **Herstel die databasis**: Deur die volgende bevel uit te voer, sal die databasis herstel word (dit moet van die grond af herbou word), maar om een of ander rede sal **geen nuwe volharding gewaarsku word totdat die stelsel herlaai word nie**.
* **root** word vereis.
```bash
# Reset the database
sfltool resettbtm
```
* **Stop die Agent**: Dit is moontlik om 'n stopsein na die agent te stuur sodat dit die gebruiker **nie sal waarsku nie** wanneer nuwe opsporings gevind word.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **Fout**: As die proses wat die volharding geskep het vinnig daarna bestaan, sal die daemon probeer om inligting daaroor te kry, misluk en nie in staat wees om die gebeurtenis aan te dui wat aandui dat 'n nuwe ding volhard nie.

Verwysings en **meer inligting oor BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
