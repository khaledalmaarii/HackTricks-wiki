# macOS TCC

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## **Basiese Inligting**

**TCC (Deursigtigheid, Toestemming en Beheer)** is 'n sekuriteitsprotokol wat fokus op die regulering van aansoektoestemmings. Sy primêre rol is om sensitiewe funksies soos **liggingdiens, kontakte, foto's, mikrofoon, kamera, toeganklikheid en volle skyftoegang** te beskerm. Deur uitdruklike gebruikerstoestemming te vereis voordat aansoeke toegang tot hierdie elemente kry, verbeter TCC privaatheid en gebruikerbeheer oor hul data.

Gebruikers kom TCC teë wanneer aansoeke toegang tot beskermde funksies versoek. Dit is sigbaar deur 'n venster wat gebruikers toelaat om **toegang goed te keur of te weier**. Verder akkommodeer TCC direkte gebruikeraksies, soos **sleep en laat val van lêers in 'n aansoek**, om toegang tot spesifieke lêers te gee, en verseker dat aansoeke slegs toegang het tot wat uitdruklik toegelaat is.

!['n Voorbeeld van 'n TCC-venster](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** word hanteer deur die **daemon** wat in `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` geleë is en gekonfigureer is in `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registreer die mach-diens `com.apple.tccd.system`).

Daar is 'n **gebruikermodus tccd** wat vir elke ingeteken gebruiker hardloop, gedefinieer in `/System/Library/LaunchAgents/com.apple.tccd.plist` wat die mach-diens `com.apple.tccd` en `com.apple.usernotifications.delegate.com.apple.tccd` registreer.

Hier kan jy sien hoe die tccd as stelsel en as gebruiker hardloop:

```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

Toestemmings word **geërf** van die ouer aansoek en die **toestemmings** word **opgespoor** gebaseer op die **Bundel-ID** en die **Ontwikkelaar-ID**.

### TCC Databasisse

Die toestemmings word dan gestoor in sekere TCC databasisse:

* Die stelselwye databasis in **`/Library/Application Support/com.apple.TCC/TCC.db`**.
* Hierdie databasis is **SIP beskerm**, sodat slegs 'n SIP-omleiding daarin kan skryf.
* Die gebruiker TCC-databasis **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** vir gebruikersvoorkeure.
* Hierdie databasis is beskerm sodat slegs prosesse met hoë TCC-voorregte soos Volle Skyftoegang daarin kan skryf (maar dit word nie deur SIP beskerm nie).

{% hint style="warning" %}
Die vorige databasisse is ook **TCC beskerm vir leestoegang**. Jy **sal nie in staat wees om** jou gewone gebruiker TCC-databasis te lees tensy dit van 'n TCC-bevoorregte proses afkomstig is.

Onthou egter dat 'n proses met hierdie hoë voorregte (soos **FDA** of **`kTCCServiceEndpointSecurityClient`**) in staat sal wees om die gebruikers TCC-databasis te skryf.
{% endhint %}

* Daar is 'n **derde** TCC-databasis in **`/var/db/locationd/clients.plist`** om kliënte aan te dui wat toegang tot **liggingdiens** toegelaat word.
* Die SIP-beskermde lêer **`/Users/carlospolop/Downloads/REG.db`** (ook beskerm teen leestoegang met TCC), bevat die **ligging** van al die **geldige TCC-databasisse**.
* Die SIP-beskermde lêer **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (ook beskerm teen leestoegang met TCC), bevat meer TCC-toegestane toestemmings.
* Die SIP-beskermde lêer **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (maar leesbaar deur enigiemand) is 'n lys van programme wat 'n TCC-uitsondering benodig.

{% hint style="success" %}
Die TCC-databasis in **iOS** is in **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

{% hint style="info" %}
Die **kennisgewingsentrum UI** kan **veranderinge in die stelsel TCC-databasis** maak:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

Nietemin kan gebruikers **reëls verwyder of navrae doen** met die **`tccutil`** opdraglyn-hulpprogram.
{% endhint %}

#### Navraag die databasisse

{% tabs %}
{% tab title="gebruiker DB" %}
{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endcode %}
{% endtab %}

{% tab title="sisteem DB" %}
{% code overflow="wrap" %}
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="success" %}
Deur beide databasisse te ondersoek, kan jy die regte wat 'n app toegelaat het, wat dit verbied het, of wat dit nie het nie (dit sal daarvoor vra).
{% endhint %}

* Die **`diens`** is die TCC **toestemming** string verteenwoordiging
* Die **`klient`** is die **bundel-ID** of **pad na binêre lêer** met die regte
* Die **`klient_tipe`** dui aan of dit 'n Bundel Identifiseerder(0) of 'n absolute pad(1) is

<details>

<summary>Hoe om uit te voer as dit 'n absolute pad is</summary>

Doen net **`launctl load jou_bin.plist`**, met 'n plist soos:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<!-- Label for the job -->
<key>Label</key>
<string>com.example.yourbinary</string>

<!-- The path to the executable -->
<key>Program</key>
<string>/path/to/binary</string>

<!-- Arguments to pass to the executable (if any) -->
<key>ProgramArguments</key>
<array>
<string>arg1</string>
<string>arg2</string>
</array>

<!-- Run at load -->
<key>RunAtLoad</key>
<true/>

<!-- Keep the job alive, restart if necessary -->
<key>KeepAlive</key>
<true/>

<!-- Standard output and error paths (optional) -->
<key>StandardOutPath</key>
<string>/tmp/YourBinary.stdout</string>
<key>StandardErrorPath</key>
<string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```

* Die **`auth_value`** kan verskillende waardes hê: geweier(0), onbekend(1), toegelaat(2), of beperk(3).
* Die **`auth_reason`** kan die volgende waardes aanneem: Fout(1), Gebruikerstoestemming(2), Gebruiker ingestel(3), Stelsel ingestel(4), Diensbeleid(5), MDM-beleid(6), Oorskrydingbeleid(7), Ontbrekende gebruiksteende(8), Vraagtyduit(9), Vooraflaai onbekend(10), Geregverklaar(11), Toepassingstipebeleid(12)
* Die **csreq** veld is daar om aan te dui hoe om die binêre lêer te verifieer om uit te voer en die TCC-toestemmings toe te ken:

```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```

* Vir meer inligting oor die **ander velde** van die tabel [**kyk na hierdie blogpos**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Jy kan ook **reeds toegekende toestemmings** vir programme in `Sisteemvoorkeure --> Sekuriteit & Privaatheid --> Privaatheid --> Lêers en Vouers` nagaan.

Gebruikers _kan_ **reëls verwyder of navrae doen** met behulp van **`tccutil`**.

**Stel TCC-toestemmings terug**

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

#### TCC Handtekeningkontroles

Die TCC **databasis** stoor die **Bundel-ID** van die aansoek, maar dit stoor ook **inligting** oor die **handtekening** om **seker te maak** dat die aansoek wat toestemming vra, die regte een is.

{% code overflow="wrap" %}
```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
{% endcode %}

Daarom sal ander toepassings wat dieselfde naam en bundel-ID gebruik nie toegang hê tot toestemmings wat aan ander programme verleen is nie.

#### Toestemmings & TCC-toestemmings

Toepassings **moet nie net** toegang tot sekere bronne **aanvra** en verkry het nie, hulle moet ook **die relevante toestemmings** hê.\
Byvoorbeeld het **Telegram** die toestemming `com.apple.security.device.camera` om **toegang tot die kamera** aan te vra. 'n **Toepassing** sonder hierdie **toestemming sal nie** die kamera kan gebruik nie (en die gebruiker sal selfs nie vir die toestemmings gevra word nie).

Nietemin, vir toepassings om toegang tot **sekere gebruikersgids** te hê, soos `~/Desktop`, `~/Downloads` en `~/Documents`, hoef hulle **geen spesifieke toestemmings** te hê nie. Die stelsel sal toegang outomaties hanteer en die gebruiker **soos nodig** versoek.

Apple se toepassings **sal nie versoekvensters genereer nie**. Hulle bevat **vooraf verleen regte** in hul **toestemmingslys**, wat beteken dat hulle **nooit 'n popup sal genereer** of in enige van die **TCC-databasisse sal verskyn nie.** Byvoorbeeld:

```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
<string>kTCCServiceReminders</string>
<string>kTCCServiceCalendar</string>
<string>kTCCServiceAddressBook</string>
</array>
```

Dit sal verhoed dat Kalender die gebruiker vra om toegang tot herinnerings, kalender en die adresboek te kry.

Afgesien van 'n paar amptelike dokumentasie oor toestemmings is dit ook moontlik om onoffisiële **interessante inligting oor toestemmings te vind in** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Sommige TCC-toestemmings is: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Daar is geen openbare lys wat almal definieer nie, maar jy kan hierdie [**lys van bekende eenhede**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) nagaan.

#### Sensitiewe onbeskermde plekke

* $HOME (self)
* $HOME/.ssh, $HOME/.aws, ens.
* /tmp

#### Gebruikersbedoeling / com.apple.macl

Soos voorheen genoem, is dit moontlik om **toegang tot 'n toepassing tot 'n lêer te verleen deur dit daarheen te sleep**. Hierdie toegang sal nie in enige TCC-databasis gespesifiseer word nie, maar as 'n **uitgebreide** **kenmerk van die lêer**. Hierdie kenmerk sal **die UUID** van die toegelate toepassing stoor:

```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```

Dit is merkwaardig dat die **`com.apple.macl`** attribuut deur die **Sandbox** bestuur word, nie deur tccd nie.

Merk ook op dat as jy 'n lêer wat die UUID van 'n toepassing op jou rekenaar toelaat na 'n ander rekenaar skuif, omdat dieselfde toepassing verskillende UID's sal hê, dit nie toegang tot daardie toepassing sal verleen nie.

Die uitgebreide attribuut `com.apple.macl` **kan nie skoongemaak word** soos ander uitgebreide eienskappe nie omdat dit deur SIP **beskerm word**. Nietemin, soos [**verduidelik in hierdie pos**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), is dit moontlik om dit te deaktiveer deur die lêer te **zip**, dit te **verwyder** en dit weer te **ontzip**.

### TCC Privesc & Omgang

#### Invoeging in TCC

As jy op 'n punt skryftoegang tot 'n TCC-databasis kry, kan jy iets soos die volgende gebruik om 'n inskrywing by te voeg (verwyder die kommentaar):

#### TCC-lading

As jy daarin geslaag het om binne 'n program met sekere TCC-toestemmings te kom, kyk na die volgende bladsy met TCC-ladinge om hulle te misbruik:

#### Outomatisering (Finder) na FDA\*

Die TCC-naam van die Outomatisering-toestemming is: **`kTCCServiceAppleEvents`**\
Hierdie spesifieke TCC-toestemming dui ook die **toepassing aan wat binne die TCC-databasis bestuur kan word** (sodat die toestemmings nie net alles toelaat om bestuur te word nie).

**Finder** is 'n toepassing wat **altyd FDA het** (selfs al verskyn dit nie in die UI nie), so as jy **Outomatisering**-voorregte daaroor het, kan jy sy voorregte misbruik om dit **sekere aksies te laat uitvoer**.\
In hierdie geval sal jou program die toestemming **`kTCCServiceAppleEvents`** oor **`com.apple.Finder`** benodig.

\# This AppleScript will copy the system TCC database into /tmposascript<\<EODtell application "Finder"set homeFolder to path to home folder as stringset sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as aliasset targetFolder to POSIX file "/tmp" as aliasduplicate file sourceFile to targetFolder with replacingend tellEODosascript<\<EODtell application "Finder"set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as aliasset targetFolder to POSIX file "/tmp" as aliasduplicate file sourceFile to targetFolder with replacingend tellEOD

Jy kan dit misbruik om **jou eie gebruiker TCC-databasis te skryf**.

Met hierdie toestemming sal jy in staat wees om **finder te vra om toegang tot TCC-beperkte mappe** en jou die lêers te gee, maar na my wete sal jy **nie in staat wees om Finder te laat arbitrêre kodes uitvoer** om sy volle FDA-toegang te misbruik nie.

Daarom sal jy nie die volle FDA-vermoëns kan misbruik nie.

Dit is die TCC-prompt om Outomatiseringsvoorregte oor Finder te kry:

<img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Let daarop dat omdat die **Automator**-toepassing die TCC-toestemming **`kTCCServiceAppleEvents`** het, kan dit **enige toepassing** beheer, soos Finder. Dus, deur die toestemming te hê om Automator te beheer, kan jy ook die **Finder** beheer met 'n kode soos die een hieronder:

</details>
