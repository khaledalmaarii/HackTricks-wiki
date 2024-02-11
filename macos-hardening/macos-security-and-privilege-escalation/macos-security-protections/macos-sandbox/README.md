# macOS Sandboks

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Basiese Inligting

MacOS Sandboks (aanvanklik genoem Seatbelt) **beperk toepassings** wat binne die sandboks loop tot die **toegelate aksies wat in die Sandboks-profiel gespesifiseer is** waarmee die app loop. Dit help om te verseker dat **die toepassing slegs verwagte hulpbronne sal benader**.

Enige app met die **bevoegdheid** **`com.apple.security.app-sandbox`** sal binne die sandboks uitgevoer word. **Apple-binêre lêers** word gewoonlik binne 'n Sandboks uitgevoer en om binne die **App Store** te publiseer, is **hierdie bevoegdheid verpligtend**. So die meeste toepassings sal binne die sandboks uitgevoer word.

Om te beheer wat 'n proses kan doen of nie kan doen nie, het die **Sandboks hake** in alle **syscalls** regoor die kernel. **Afhanklik** van die **bevoegdhede** van die app sal die Sandboks sekere aksies **toelaat**.

Sommige belangrike komponente van die Sandboks is:

* Die **kernel-uitbreiding** `/System/Library/Extensions/Sandbox.kext`
* Die **privaat-raamwerk** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* 'n **Daemon** wat in userland loop `/usr/libexec/sandboxd`
* Die **houers** `~/Library/Containers`

Binne die houers-vouer kan jy **'n vouer vir elke app wat binne die sandboks uitgevoer word** vind met die naam van die bundel-ID:
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
Binne elke bundel-ID-vouer kan jy die **plist** en die **Data-gids** van die App vind:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
Let daarop dat selfs al is die simboliese skakels daar om uit die Sandboks te "ontsnap" en toegang tot ander lêers te verkry, moet die App steeds **toestemmings** hê om daartoe toegang te verkry. Hierdie toestemmings is binne die **`.plist`**.
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
Alles wat deur 'n Sandboxed-toepassing geskep/gewysig word, sal die **karantynatribuut** kry. Dit sal 'n sandboksruimte voorkom deur Gatekeeper te aktiveer as die sandboks-toepassing iets probeer uitvoer met **`open`**.
{% endhint %}

### Sandboksprofiel

Die Sandboksprofiel is konfigurasie lêers wat aandui wat in daardie **Sandboks** toegelaat/verbode is. Dit gebruik die **Sandbox Profile-taal (SBPL)**, wat die [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)) programmeer taal gebruik.

Hier kan jy 'n voorbeeld vind:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
Kyk na hierdie [**navorsing**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **om meer aksies te sien wat toegelaat of geweier kan word.**
{% endhint %}

Belangrike **sisteemdiens**e loop ook binne hul eie aangepaste **sandbox**, soos die `mdnsresponder`-diens. Jy kan hierdie aangepaste **sandbox-profiel**e sien binne:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* Ander sandbox-profiel kan nagegaan word by [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

**App Store**-toepassings gebruik die **profiel** **`/System/Library/Sandbox/Profiles/application.sb`**. Jy kan in hierdie profiel nagaan hoe toekennings soos **`com.apple.security.network.server`** 'n proses toelaat om die netwerk te gebruik.

SIP is 'n Sandbox-profiel genaamd platform\_profile in /System/Library/Sandbox/rootless.conf

### Voorbeelde van Sandbox-profiel

Om 'n toepassing met 'n **spesifieke sandbox-profiel** te begin, kan jy gebruik maak van:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% code title="touch.sb" %}

```
(version 1)
(deny default)

(allow file-read-metadata)
(allow file-write-metadata)

(allow file-read-data (literal "/path/to/file"))
(allow file-write-data (literal "/path/to/file"))

(allow file-read-data (subpath "/path/to/directory/"))
(allow file-write-data (subpath "/path/to/directory/"))

(allow file-read-data (regex #"^/path/to/file\d{3}$"))
(allow file-write-data (regex #"^/path/to/file\d{3}$"))
```

{% endcode %}
{% endtab %}

{% tab title="touch" %}
{% code title="touch.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
{% code title="touch2.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
{% code title="touch3.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Let wel dat die **Apple- geskrewe sagteware** wat op **Windows** loop **nie addisionele sekuriteitsvoorsorgmaatreëls** soos toepassingssandboxing het nie.
{% endhint %}

Voorbeelde van omseilings:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (hulle kan lêers buite die sandbox skryf met 'n naam wat begin met `~$`).

### MacOS Sandbakkie Profiele

macOS stoor stelselsandbakkieprofiel in twee plekke: **/usr/share/sandbox/** en **/System/Library/Sandbox/Profiles**.

En as 'n derdeparty-toepassing die _**com.apple.security.app-sandbox**_ toekenning dra, pas die stelsel die **/System/Library/Sandbox/Profiles/application.sb** profiel toe op daardie proses.

### **iOS Sandbakkie Profiel**

Die verstekprofiel word **houer** genoem en ons het nie die SBPL-tekstrepsentasie nie. In die geheue word hierdie sandbakkie voorgestel as 'n Toelaat/Weier binêre boom vir elke toestemming van die sandbakkie.

### Foutopsporing en Omseiling van Sandbakkie

Op macOS, in teenstelling met iOS waar prosesse van die begin af deur die kernel gesandbakkieer word, **moet prosesse self besluit om in die sandbakkie in te gaan**. Dit beteken op macOS word 'n proses nie deur die sandbakkie beperk nie totdat dit aktief besluit om daarin te gaan.

Prosesse word outomaties gesandbakkieer vanuit die gebruikersruimte wanneer hulle begin as hulle die toekenning het: `com.apple.security.app-sandbox`. Vir 'n gedetailleerde verduideliking van hierdie proses, kyk na:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Kontroleer PID-voorregte**

[**Volgens hierdie**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), kan die **`sandbox_check`** (dit is 'n `__mac_syscall`), nagaan **of 'n operasie toegelaat word of nie** deur die sandbakkie in 'n sekere PID.

Die [**sbtool-hulpmiddel**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) kan nagaan of 'n PID 'n sekere aksie kan uitvoer:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Aangepaste SBPL in App Store-toepassings

Dit is moontlik vir maatskappye om hul toepassings te laat loop **met aangepaste Sandboksprofiel** (in plaas van die verstek een). Hulle moet die toekenning **`com.apple.security.temporary-exception.sbpl`** gebruik wat deur Apple gemagtig moet word.

Dit is moontlik om die definisie van hierdie toekenning te kontroleer in **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Dit sal die string na hierdie entitlement evalueer as 'n Sandboksprofiel.

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
