# macOS Sandbox

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

MacOS Sandbox (aanvanklik Seatbelt genoem) **beperk toepassings** wat binne die sandbox loop tot die **toegelate aksies gespesifiseer in die Sandbox-profiel** waarmee die toepassing loop. Dit help om te verseker dat **die toepassing slegs verwagte hulpbronne sal benader**.

Enige toepassing met die **regte** **`com.apple.security.app-sandbox`** sal binne die sandbox uitgevoer word. **Apple-binaries** word gewoonlik binne 'n Sandbox uitgevoer en om in die **App Store** te publiseer, is **hierdie regte verpligtend**. So die meeste toepassings sal binne die sandbox uitgevoer word.

Om te beheer wat 'n proses kan of nie kan doen nie, het die **Sandbox haakplekke** in alle **syscalls** regdeur die kern. **Afhangende** van die **regte** van die toepassing, sal die Sandbox sekere aksies **toelaat**.

Sommige belangrike komponente van die Sandbox is:

* Die **kernuitbreiding** `/System/Library/Extensions/Sandbox.kext`
* Die **privaat raamwerk** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* 'n **daemon** wat in userland loop `/usr/libexec/sandboxd`
* Die **houers** `~/Library/Containers`

Binne die houers-gids kan jy **'n gids vir elke toepassing wat sandboxed uitgevoer word** vind met die naam van die bundel-id:
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
Binne elke bundel-id-gids kan jy die **plist** en die **Data-gids** van die App vind:
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
Let daarop dat selfs al is die symlinks daar om te "ontsnap" uit die Sandbox en ander mappen te benader, moet die App steeds **toestemming hê** om toegang daartoe te verkry. Hierdie toestemmings is binne die **`.plist`**.
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
Alles wat deur 'n Sandboxed toepassing geskep/gewysig word, sal die **kwarantyn-attribuut** ontvang. Dit sal 'n sandbox ruimte voorkom deur Gatekeeper te aktiveer as die sandbox toepassing probeer om iets met **`open`** uit te voer.
{% endhint %}

### Sandbox Profiele

Die Sandbox profiele is konfigurasie lêers wat aandui wat in daardie **Sandbox** **toegelaat/verbode** gaan word. Dit gebruik die **Sandbox Profiel Taal (SBPL)**, wat die [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)) programmeertaal gebruik.

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
Kontroleer hierdie [**navorsing**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **om meer aksies te kontroleer wat toegelaat of geweier kan word.**
{% endhint %}

Belangrike **stelseldienste** loop ook binne hul eie pasgemaakte **sandbox** soos die `mdnsresponder` diens. Jy kan hierdie pasgemaakte **sandbox-profiele** binne kyk:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* Ander sandbox-profiele kan nagegaan word in [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

**App Store** toepassings gebruik die **profiel** **`/System/Library/Sandbox/Profiles/application.sb`**. Jy kan in hierdie profiel kyk hoe regte soos **`com.apple.security.network.server`** 'n proses toelaat om die netwerk te gebruik.

SIP is 'n Sandbox-profiel genaamd platform\_profile in /System/Library/Sandbox/rootless.conf

### Sandbox Profiel Voorbeelde

Om 'n toepassing met 'n **spesifieke sandbox-profiel** te begin, kan jy gebruik:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
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
{% endcode %}

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
Let daarop dat die **Apple-geskrewe** **programmatuur** wat op **Windows** loop **nie addisionele sekuriteitsmaatreëls** het nie, soos toepassingsandboxing.
{% endhint %}

Bypasses voorbeelde:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (hulle kan lêers buite die sandbox skryf waarvan die naam met `~$` begin).

### MacOS Sandbox Profiele

macOS stoor stelselsandboxprofiele in twee plekke: **/usr/share/sandbox/** en **/System/Library/Sandbox/Profiles**.

En as 'n derdeparty-toepassing die _**com.apple.security.app-sandbox**_ regte het, pas die stelsel die **/System/Library/Sandbox/Profiles/application.sb** profiel op daardie proses toe.

### **iOS Sandbox Profiel**

Die standaardprofiel word **container** genoem en ons het nie die SBPL teksverteenwoordiging nie. In geheue word hierdie sandbox verteenwoordig as 'n Toestaan/Weier binaire boom vir elke toestemming van die sandbox.

### Debug & Bypass Sandbox

Op macOS, anders as iOS waar prosesse vanaf die begin deur die kern in 'n sandbox geplaas word, **moet prosesse self in die sandbox optree**. Dit beteken op macOS is 'n proses nie deur die sandbox beperk nie totdat dit aktief besluit om daarin te gaan.

Prosesse word outomaties in 'n sandbox geplaas vanaf gebruikersland wanneer hulle begin as hulle die regte het: `com.apple.security.app-sandbox`. Vir 'n gedetailleerde verduideliking van hierdie proses kyk:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Kontroleer PID Regte**

[**Volgens hierdie**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), kan die **`sandbox_check`** (dit is 'n `__mac_syscall`), **kontroleer of 'n operasie toegelaat word of nie** deur die sandbox in 'n sekere PID.

Die [**instrument sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) kan kontroleer of 'n PID 'n sekere aksie kan uitvoer:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Custom SBPL in App Store apps

Dit kan moontlik wees vir maatskappye om hul toepassings te laat werk **met pasgemaakte Sandbox-profiele** (in plaas van met die standaard een). Hulle moet die regte **`com.apple.security.temporary-exception.sbpl`** gebruik wat deur Apple goedgekeur moet word.

Dit is moontlik om die definisie van hierdie regte in **`/System/Library/Sandbox/Profiles/application.sb:`** te kontroleer.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Dit sal **die string na hierdie regte** as 'n Sandbox-profiel evaluer.

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsieplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PR's in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
