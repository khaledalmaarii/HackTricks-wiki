# macOS Sekuriteitsbeskerming

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Toegangbeheerder

Toegangbeheerder word gewoonlik gebruik om te verwys na die kombinasie van **Kwarantyn + Toegangbeheerder + XProtect**, 3 macOS-sekuriteitsmodules wat sal probeer om **gebruikers te keer om potensieel skadelike sagteware wat afgelaai is, uit te voer**.

Meer inligting in:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Proseshanterings

### SIP - Sisteemintegriteitsbeskerming

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandboks

MacOS Sandboks **beperk toepassings** wat binne die sandboks hardloop tot die **toegelate aksies wat in die Sandboksprofiel gespesifiseer is** waarmee die toepassing hardloop. Dit help om te verseker dat **die toepassing slegs verwagte hulpbronne sal benader**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Deursigtigheid, Toestemming en Beheer**

**TCC (Deursigtigheid, Toestemming en Beheer)** is 'n sekuriteitsraamwerk. Dit is ontwerp om die toestemmings van toepassings te **bestuur**, spesifiek deur hul toegang tot sensitiewe funksies te reguleer. Dit sluit elemente soos **liggingdiens, kontakte, foto's, mikrofoon, kamera, toeganklikheid en volle skyftoegang** in. TCC verseker dat programme hierdie funksies slegs kan benader nadat eksplisiete gebruikerstoestemming verkry is, wat privaatheid versterk en beheer oor persoonlike data bied.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Lancering/Omgewingsbeperkings & Vertrouenskas

Lanceringsbeperkings in macOS is 'n sekuriteitskenmerk om **prosesinisiëring te reguleer** deur te definieer **wie** 'n proses kan begin, **hoe**, en **van waar**. Ingevoer in macOS Ventura, kategoriseer hulle stelselbinêres in beperkingskategorieë binne 'n **vertrouenskas**. Elke uitvoerbare binêre het vasgestelde **reëls** vir sy **aanvang**, insluitend **self**, **ouer**, en **verantwoordelike** beperkings. Uitgebrei na derdeparty-apps as **Omgewing** Beperkings in macOS Sonoma, help hierdie kenmerke om potensiële stelseluitbuitings te verminder deur proseslanceringsvoorwaardes te regeer.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Malwareverwyderingswerktuig

Die Malwareverwyderingswerktuig (MRT) is 'n ander deel van macOS se sekuriteitsinfrastruktuur. Soos die naam aandui, is MRT se hooffunksie om **bekende malware van geïnfekteerde stelsels te verwyder**.

Sodra malware op 'n Mac opgespoor word (of deur XProtect of op 'n ander manier), kan MRT gebruik word om die malware outomaties te **verwyder**. MRT werk stil in die agtergrond en hardloop tipies wanneer die stelsel opgedateer word of wanneer 'n nuwe malware-definisie afgelaai word (dit lyk asof die reëls wat MRT moet gebruik om malware op te spoor, binne die binêre lê).

Terwyl beide XProtect en MRT deel is van macOS se sekuriteitsmaatreëls, verrig hulle verskillende funksies:

* **XProtect** is 'n voorkomende werktuig. Dit **kontroleer lêers terwyl hulle afgelaai word** (via sekere toepassings), en as dit enige bekende tipes malware opspoor, **voorkom dit dat die lêer oopgemaak word**, en voorkom dus dat die malware jou stelsel in die eerste plek infekteer.
* **MRT** daarenteen is 'n **reaktiewe werktuig**. Dit werk nadat malware op 'n stelsel opgespoor is, met die doel om die oortredende sagteware te verwyder om die stelsel skoon te maak.

Die MRT-toepassing is geleë in **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Agtergrondtakebestuur

**macOS** waarsku nou **elke keer as 'n werktuig 'n bekende **tegniek gebruik om kode-uitvoering vol te hou** (soos Aanmeldingsitems, Daemons...), sodat die gebruiker beter weet **watter sagteware volhou**.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

Dit hardloop met 'n **daemon** geleë in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` en die **agent** in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Die manier waarop **`backgroundtaskmanagementd`** weet dat iets in 'n volgehoue vouer geïnstalleer is, is deur **die FSEvents te kry** en sommige **hanteraars** daarvoor te skep.

Daarbenewens is daar 'n plist-lêer wat **bekende toepassings** bevat wat gereeld volhou wat deur Apple onderhou word en geleë is in: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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
### Opsomming

Dit is moontlik om **alle** geconfigureerde agtergronditems op te som met die Apple-opdraggereelwerktuig:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Boonop, dit is ook moontlik om hierdie inligting te lys met [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Hierdie inligting word gestoor in **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** en die Terminal benodig FDA.

### Mors met BTM

Wanneer 'n nuwe volharding gevind word, 'n gebeurtenis van die tipe **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Enige manier om hierdie gebeurtenis te **verhoed** om gestuur te word of die **agent om die gebruiker te waarsku** sal 'n aanvaller help om die BTM te _**omseil**_.

* **Herstel die databasis**: Deur die volgende bevel uit te voer, sal die databasis herstel word (dit behoort van die grond af herbou te word), maar, om een of ander rede, na die uitvoering hiervan, **sal geen nuwe volharding gewaarsku word totdat die stelsel herlaai word**.
* **root** is vereis.
```bash
# Reset the database
sfltool resettbtm
```
* **Stop die Agente**: Dit is moontlik om 'n stopsein na die agente te stuur sodat dit die gebruiker **nie sal waarsku nie** wanneer nuwe opsporings gevind word.
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
* **Fout**: As die **proses wat die volharding geskep het vinnig daarna bestaan**, sal die daimon probeer om **inligting daaroor te kry**, **misluk**, en **nie in staat wees om die gebeurtenis** aan te dui dat 'n nuwe ding volhard nie.

Verwysings en **meer inligting oor BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
